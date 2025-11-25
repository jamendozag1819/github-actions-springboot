#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
gate_evaluator.py
------------------
Python evaluator for Snyk + Sonar results based on GATE_SPECIFICATIONS.md

Usage:
    python gate_evaluator.py \
        --snyk results/security \
        --sonar results/quality \
        --thresholds gating/thresholds.json \
        --params gating/sonar-params.json \
        --output gating/gate-result.json \
        --target PROD \
        --ref refs/heads/release/1.0.0

Exit codes:
    0 → PASS, WARN, PASS_WITH_EXCEPTION
    1 → FAIL
"""

import os
import json
import argparse
from pathlib import Path


# -------------------------------------------------------
# Helpers
# -------------------------------------------------------

def read_json(file_path):
    if not file_path or not os.path.exists(file_path):
        return None
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def find_file(directory, candidates):
    if not directory or not os.path.exists(directory):
        return None

    files = os.listdir(directory)

    # Exact match
    for name in candidates:
        if name.lower() in [f.lower() for f in files]:
            return os.path.join(directory, name)

    # Contains match
    for f in files:
        for candidate in candidates:
            if candidate.lower() in f.lower():
                return os.path.join(directory, f)

    return None


# -------------------------------------------------------
# Load results
# -------------------------------------------------------

def load_snyk_results(directory):
    candidates = [
        "snyk-results.json",
        "snyk-output.json",
        "results.json",
        "security-results.json"
    ]
    f = find_file(directory, candidates)
    return read_json(f)


def load_sonar_results(directory):
    candidates = [
        "sonar-report.json",
        "sonar-results.json",
        "project_status.json",
        "sonar-quality.json",
        "scan-report.json"
    ]
    f = find_file(directory, candidates)
    return read_json(f)


# -------------------------------------------------------
# Thresholds
# -------------------------------------------------------

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
        "approved_sonar_params": [
            "sonar.coverage.exclusions",
            "sonar.cpd.exclusions"
        ]
    }


def merge_thresholds(base, overrides):
    if not overrides:
        return base

    merged = json.loads(json.dumps(base))  # deep copy

    if "snyk" in overrides:
        merged["snyk"].update(overrides["snyk"])

    if "sonarqube" in overrides:
        merged["sonarqube"].update(overrides["sonarqube"])

    return merged


# -------------------------------------------------------
# Gate evaluation
# -------------------------------------------------------

def evaluate_snyk(snyk_json, t):
    results = []
    vulns = snyk_json.get("vulnerabilities", []) if snyk_json else []

    sev_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for v in vulns:
        sev = v.get("severity", "").lower()
        if sev in sev_count:
            sev_count[sev] += 1

    # GATR-03 Critical
    status = "PASS" if sev_count["critical"] == 0 else "WARN"
    results.append({
        "id": "gatr-03",
        "status": status,
        "critical_vulnerabilities": sev_count["critical"],
        "threshold": t["snyk"]["critical"]
    })

    # GATR-01 High
    status = "PASS" if sev_count["high"] <= t["snyk"]["high"] else "WARN"
    results.append({
        "id": "gatr-01",
        "status": status,
        "high_vulnerabilities": sev_count["high"],
        "threshold": t["snyk"]["high"]
    })

    # GATR-02 Medium
    status = "PASS" if sev_count["medium"] <= t["snyk"]["medium"] else "WARN"
    results.append({
        "id": "gatr-02",
        "status": status,
        "medium_vulnerabilities": sev_count["medium"],
        "threshold": t["snyk"]["medium"]
    })

    return results


def evaluate_sonar(sonar_json, t, used_params):
    results = []

    if not sonar_json:
        return [{
            "id": "gatr-07",
            "status": "WARN",
            "message": "Sonar results missing"
        }]

    metrics = sonar_json.get("metrics", {})
    ratings = metrics.get("ratings", {})

    coverage = metrics.get("coverage")
    bugs = metrics.get("bugs")
    vulns = metrics.get("vulnerabilities")
    code_smells = metrics.get("code_smells")
    ratings = metrics.get("ratings")
    # GATR-07 (developer thresholds)
    issues = []

    if coverage is not None and coverage < t["sonarqube"]["coverage"]:
        issues.append(f"Coverage {coverage} < {t['sonarqube']['coverage']}")

    if bugs is not None and bugs > t["sonarqube"]["bugs"]:
        issues.append(f"Bugs {bugs} > {t['sonarqube']['bugs']}")

    if vulns is not None and vulns > t["sonarqube"]["vulnerabilities"]:
        issues.append(f"Vulnerabilities {vulns} > {t['sonarqube']['vulnerabilities']}")

    if code_smells is not None and code_smells > t["sonarqube"]["code_smells"]:
        issues.append(f"Code smells {code_smells} > {t['sonarqube']['code_smells']}")

    if ratings.security is not None and ratings.security == t["sonarqube"]["security_rating"]:
        issues.append(f"Code smells {ratings.security} > {t['sonarqube']['security_rating']}")

    if ratings.maintainability is not None and ratings.maintainability == t["sonarqube"]["maintainability_rating"]:
        issues.append(f"Code smells {ratings.maintainability} > {t['sonarqube']['maintainability_rating']}")

    if ratings.reliability is not None and ratings.reliability == t["sonarqube"]["reliability_rating"]:
        issues.append(f"Code smells {ratings.reliability} > {t['sonarqube']['reliability_rating']}")

    results.append({
        "id": "gatr-07",
        "status": "PASS" if not issues else "WARN",
        "issues": issues
    })

    # GATR-08 (quality gate)
    q_status = sonar_json.get("quality_gate", {}).get("status", "OK")

    results.append({
        "id": "gatr-08",
        "status": "FAIL" if q_status.upper() in ("ERROR", "FAIL") else "PASS",
        "quality_gate_status": q_status
    })

    # GATR-09 (approved sonar params)
    disallowed = [p for p in used_params if p not in t["approved_sonar_params"]]

    results.append({
        "id": "gatr-09",
        "status": "FAIL" if disallowed else "PASS",
        "disallowed": disallowed,
        "allowed": t["approved_sonar_params"]
    })

    return results


def evaluate_branch(ref, target_env):
    allowed = [
        "refs/heads/main",
    ]

    if ref.startswith("refs/heads/release/"):
        return {"id": "gatr-14", "status": "PASS", "branch": ref, "env": target_env}

    if target_env in ("PROD", "UAT") and ref not in allowed:
        return {
            "id": "gatr-14",
            "status": "FAIL",
            "branch": ref,
            "env": target_env,
            "message": "Only main or release/* can deploy to UAT/PROD"
        }

    return {"id": "gatr-14", "status": "PASS", "branch": ref, "env": target_env}


# -------------------------------------------------------
# Final decision
# -------------------------------------------------------

def decide_final(gates):
    enforcing = {"gatr-08", "gatr-09", "gatr-14"}
    final = "PASS"

    for g in gates:
        if g["id"] in enforcing and g["status"] == "FAIL":
            return "FAIL"
        if g["status"] == "WARN" and final == "PASS":
            final = "WARN"

    return final


# -------------------------------------------------------
# Main
# -------------------------------------------------------

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

    base = default_thresholds()
    overrides = read_json(args.thresholds)
    thresholds = merge_thresholds(base, overrides)

    snyk_json = load_snyk_results(args.snyk)
    sonar_json = load_sonar_results(args.sonar)
    sonar_params = read_json(args.params) or []

    gates = []
    gates.extend(evaluate_snyk(snyk_json, thresholds))
    gates.extend(evaluate_sonar(sonar_json, thresholds, sonar_params))
    gates.append(evaluate_branch(args.ref, args.target))

    final = decide_final(gates)

    out_dir = Path(args.output).parent
    out_dir.mkdir(parents=True, exist_ok=True)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump({"final_decision": final, "gates": gates}, f, indent=2)

    print(f"Gate evaluation: {final}")
    print(f"Output written to: {args.output}")

    exit(1 if final == "FAIL" else 0)


if __name__ == "__main__":
    main()
