#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
gate_evaluator.py
------------------
Evaluador Python para resultados de Snyk + SonarQube, basado en las reglas
definidas en GATE_SPECIFICATIONS.md.

Este script:
    - Carga resultados de Snyk (SCA y SAST)
    - Carga resultados de SonarQube
    - Aplica umbrales de calidad predefinidos o personalizados
    - Evalúa múltiples reglas GATR-XX
    - Genera un archivo JSON final con el resultado
    - Retorna un código de salida para enforcement

Uso:
    python gate_evaluator.py \
        --snyk results/security \
        --sonar results/quality \
        --thresholds gating/thresholds.json \
        --params gating/sonar-params.json \
        --output gating/gate-result.json \
        --target PROD \
        --ref refs/heads/release/1.0.0

Exit Codes:
    0 → PASS / WARN / PASS_WITH_EXCEPTION
    1 → FAIL
"""

import os
import json
import argparse
import requests
from datetime import datetime
from pathlib import Path


# ======================================================================
# Jira Exception Checker
# ======================================================================

def jira_check_exception(gate_id, app_id):
    """
    Consulta Jira para verificar si existe una excepción aprobada
    para un gate específico.
    """
    JIRA_URL = os.getenv("JIRA_URL")
    JIRA_USER = os.getenv("JIRA_USER")
    JIRA_TOKEN = os.getenv("JIRA_API_TOKEN")
    JIRA_PROJECT = os.getenv("JIRA_PROJECT", "GATES")

    if not all([JIRA_URL, JIRA_USER, JIRA_TOKEN]):
        print("⚠ Jira integration not configured. Skipping.")
        return {"approved": False}

    today = datetime.utcnow().strftime("%Y-%m-%d")

    jql = f'''
        project = {JIRA_PROJECT} AND
        cf_gate_id = "{gate_id}" AND
        cf_application_id = "{app_id}" AND
        cf_exception_approval_status = "DECISION MADE" AND
        cf_exception_approval_decision = "Approved" AND
        cf_exception_expiry_date >= "{today}"
    '''

    url = f"{JIRA_URL}/rest/api/2/search"

    try:
        response = requests.get(
            url,
            params={"jql": jql},
            auth=(JIRA_USER, JIRA_TOKEN),
            headers={"Content-Type": "application/json"}
        )
    except Exception as e:
        print(f"Error contacting Jira: {e}")
        return {"approved": False}

    if response.status_code != 200:
        print(f"Jira query failed: HTTP {response.status_code}")
        return {"approved": False}

    data = response.json()

    if data.get("total", 0) > 0:
        issue = data["issues"][0]
        return {
            "approved": True,
            "issue_key": issue["key"],
            "expiry": issue["fields"].get("cf_exception_expiry_date")
        }

    return {"approved": False}

# ======================================================================
# Utility Helpers
# ======================================================================

def read_json(path):
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return None


def find_file(directory, candidates):
    if not directory or not os.path.exists(directory):
        return None

    files = os.listdir(directory)

    # exact match
    for c in candidates:
        if c.lower() in [f.lower() for f in files]:
            return os.path.join(directory, c)

    # partial match
    for f in files:
        for c in candidates:
            if c.lower() in f.lower():
                return os.path.join(directory, f)

    return None


# ======================================================================
# Load Snyk & SonarQube Results
# ======================================================================

def load_snyk_results(directory):
    candidates = [
        "snyk-results.json", "snyk-output.json", "results.json",
        "security-results.json", "snyk-report.json"
    ]
    f = find_file(directory, candidates)
    return read_json(f)


def load_sonar_results(directory):
    candidates = [
        "sonar-report.json", "sonar-results.json", "project_status.json",
        "sonar-quality.json", "scan-report.json"
    ]
    f = find_file(directory, candidates)
    return read_json(f)


# ======================================================================
# Thresholds
# ======================================================================

def default_thresholds():
    return {
        "snyk": {"critical": 0, "high": 5, "medium": 20},
        "sonarqube": {
            "coverage": 80,
            "bugs": 5,
            "vulnerabilities": 0,
            "code_smells": 50,
            "security_rating": "A",
            "reliability_rating": "A",
            "maintainability_rating": "B",
            "tech_debt_minutes": 480,
            "express_lane": {
                "coverage_threshold": 80,
                "test_success_threshold": 80,
                "max_security_rating": "B",
                "max_reliability_rating": "C"
            }
        },
        "approved_sonar_params": ["sonar.coverage.exclusions", "sonar.cpd.exclusions"]
    }


def merge_thresholds(base, overrides):
    if not overrides:
        return base
    merged = json.loads(json.dumps(base))
    if "snyk" in overrides:
        merged["snyk"].update(overrides["snyk"])
    if "sonarqube" in overrides:
        merged["sonarqube"].update(overrides["sonarqube"])
    return merged


# ======================================================================
# Evaluation: Snyk
# ======================================================================

def evaluate_snyk(snyk_json, t):
    results = []
    vulns = snyk_json.get("vulnerabilities", []) if snyk_json else []

    sev = {"critical": 0, "high": 0, "medium": 0}

    for v in vulns:
        s = v.get("severity", "").lower()
        if s in sev:
            sev[s] += 1

    # GATR-03 Critical
    results.append({
        "id": "gatr-03",
        "status": "PASS" if sev["critical"] == t["snyk"]["critical"] else "WARN",
        "count": sev["critical"],
        "threshold": t["snyk"]["critical"]
    })

    # GATR-01 High
    results.append({
        "id": "gatr-01",
        "status": "PASS" if sev["high"] <= t["snyk"]["high"] else "WARN",
        "count": sev["high"],
        "threshold": t["snyk"]["high"]
    })

    # GATR-02 Medium
    results.append({
        "id": "gatr-02",
        "status": "PASS" if sev["medium"] <= t["snyk"]["medium"] else "WARN",
        "count": sev["medium"],
        "threshold": t["snyk"]["medium"]
    })

    return results


# ======================================================================
# Evaluation: SonarQube
# ======================================================================

def evaluate_sonar(sonar_json, t, used_params):
    if not sonar_json:
        return [{"id": "gatr-07", "status": "WARN", "message": "Missing Sonar results"}]

    metrics = sonar_json.get("metrics", {})
    ratings = metrics.get("ratings", {})

    issues = []

    def fail_if(cond, msg):
        if cond:
            issues.append(msg)

    fail_if(metrics.get("coverage") < t["sonarqube"]["coverage"],
            f"Coverage {metrics.get('coverage')} < {t['sonarqube']['coverage']}")

    fail_if(metrics.get("bugs") > t["sonarqube"]["bugs"],
            f"Bugs exceed {t['sonarqube']['bugs']}")

    fail_if(metrics.get("vulnerabilities") > t["sonarqube"]["vulnerabilities"],
            f"Vulns exceed {t['sonarqube']['vulnerabilities']}")

    fail_if(metrics.get("code_smells") > t["sonarqube"]["code_smells"],
            f"Code smells exceed {t['sonarqube']['code_smells']}")

    fail_if(ratings.get("security") != t["sonarqube"]["security_rating"],
            "Security rating mismatch")

    fail_if(ratings.get("reliability") != t["sonarqube"]["reliability_rating"],
            "Reliability rating mismatch")

    fail_if(ratings.get("maintainability") != t["sonarqube"]["maintainability_rating"],
            "Maintainability rating mismatch")

    # GATR-07
    g07 = {
        "id": "gatr-07",
        "status": "PASS" if not issues else "WARN",
        "issues": issues
    }

    # GATR-08 Quality Gate
    q_status = sonar_json.get("quality_gate", {}).get("status", "OK")
    g08 = {
        "id": "gatr-08",
        "status": "FAIL" if q_status.upper() in ["ERROR", "FAIL"] else "PASS",
        "quality_gate_status": q_status
    }

    # GATR-09 Allowed parameters
    disallowed = [p for p in used_params if p not in t["approved_sonar_params"]]
    g09 = {
        "id": "gatr-09",
        "status": "FAIL" if disallowed else "PASS",
        "disallowed": disallowed
    }

    return [g07, g08, g09]


# ======================================================================
# GATR-14 Branch Validation
# ======================================================================

def evaluate_branch(ref, env):
    if ref.startswith("refs/heads/release/"):
        return {"id": "gatr-14", "status": "PASS", "branch": ref}

    if env in ("PROD", "UAT") and ref != "refs/heads/main":
        return {"id": "gatr-14", "status": "FAIL", "branch": ref,
                "message": "Only main or release/* allowed"}

    return {"id": "gatr-14", "status": "PASS", "branch": ref}


# ======================================================================
# GATR-10 Express Lane
# ======================================================================

def evaluate_express_lane(sonar_json, t):
    if not sonar_json:
        return {"id": "gatr-10", "status": "WARN", "message": "Missing Sonar"}

    metrics = sonar_json.get("metrics", {})
    ratings = metrics.get("ratings", {})
    new = metrics.get("new_ratings", {})

    e = t["sonarqube"]["express_lane"]
    issues = []

    if metrics.get("coverage") < e["coverage_threshold"]:
        issues.append("Coverage too low")

    if metrics.get("test_success_rate") < e["test_success_threshold"]:
        issues.append("Test success too low")

    if ratings.get("security") > e["max_security_rating"]:
        issues.append("Security rating too low")

    if ratings.get("reliability") > e["max_reliability_rating"]:
        issues.append("Reliability rating too low")

    if new.get("security") not in (None, "A"):
        issues.append("New-code security != A")

    if new.get("reliability") not in (None, "A"):
        issues.append("New-code reliability != A")

    return {
        "id": "gatr-10",
        "status": "PASS" if not issues else "WARN",
        "issues": issues
    }


# ======================================================================
# FINAL DECISION
# ======================================================================

def decide_final(gates):
    enforcing = {"gatr-08", "gatr-09", "gatr-14"}
    final = "PASS"
    for g in gates:
        if g["id"] in enforcing and g["status"] == "FAIL":
            return "FAIL_PENDING_EXCEPTION"
        if g["status"] == "WARN" and final == "PASS":
            final = "WARN"
    return final


# ======================================================================
# MAIN
# ======================================================================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--snyk")
    parser.add_argument("--sonar")
    parser.add_argument("--thresholds")
    parser.add_argument("--params")
    parser.add_argument("--output", default="gating/gate-result.json")
    parser.add_argument("--target", default="DEV")
    parser.add_argument("--ref", default="refs/heads/main")
    args = parser.parse_args()

    # Cargar thresholds
    base = default_thresholds()
    overrides = read_json(args.thresholds)
    thresholds = merge_thresholds(base, overrides)

    # Cargar resultados
    snyk_json = load_snyk_results(args.snyk)
    sonar_json = load_sonar_results(args.sonar)
    sonar_params = read_json(args.params) or []

    # Ejecutar evaluaciones
    gates = []
    gates.extend(evaluate_snyk(snyk_json, thresholds))
    gates.append(evaluate_express_lane(sonar_json, thresholds))
    gates.extend(evaluate_sonar(sonar_json, thresholds, sonar_params))
    gates.append(evaluate_branch(args.ref, args.target))

    # Decisión sin excepciones
    final = decide_final(gates)

    # Si falla un gate ENFORCING → buscar excepción en Jira
    if final == "FAIL_PENDING_EXCEPTION":
        app_id = os.getenv("APP_ID", "unknown")
        print("Checking Jira for exception approvals...")

        failed = [
            g for g in gates
            if g["id"] in ("gatr-08", "gatr-09", "gatr-14") and g["status"] == "FAIL"
        ]

        exception_found = False

        for g in failed:
            r = jira_check_exception(g["id"], app_id)
            if r.get("approved"):
                g["status"] = "PASS_WITH_EXCEPTION"
                g["exception_issue"] = r["issue_key"]
                g["exception_expiry"] = r["expiry"]
                exception_found = True
                print(f"✔ Exception approved for {g['id']} ({r['issue_key']})")

        if exception_found:
            final = "PASS_WITH_EXCEPTION"
        else:
            final = "FAIL"

    # Crear carpeta
    out_dir = Path(args.output).parent
    out_dir.mkdir(parents=True, exist_ok=True)

    # Guardar salida
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump({"final_decision": final, "gates": gates}, f, indent=2)

    print(f"Gate evaluation: {final}")
    print(f"Output written to: {args.output}")

    exit(1 if final == "FAIL" else 0)


if __name__ == "__main__":
    main()
