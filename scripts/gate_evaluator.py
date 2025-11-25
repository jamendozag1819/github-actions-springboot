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
    - Evalúa múltiples reglas GATR-XX que determinan si el proyecto
      puede avanzar en el pipeline (DEV, UAT, PROD)
    - Genera un archivo JSON final con todas las evaluaciones
    - Devuelve un código de salida para bloquear o permitir despliegues

Uso:
    python gate_evaluator.py \
        --snyk results/security \
        --sonar results/quality \
        --thresholds gating/thresholds.json \
        --params gating/sonar-params.json \
        --output gating/gate-result.json \
        --target PROD \
        --ref refs/heads/release/1.0.0

Códigos de salida:
    0 → PASS, WARN o PASS_WITH_EXCEPTION
    1 → FAIL (bloquea despliegue)
"""

import os
import json
import argparse
from pathlib import Path


# ================================================================
# Helpers (funciones auxiliares)
# ================================================================

def read_json(file_path):
    """
    Lee un archivo JSON si existe y lo devuelve como dict.
    Si no existe o está corrupto, devuelve None.
    """
    if not file_path or not os.path.exists(file_path):
        return None
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def find_file(directory, candidates):
    """
    Busca dentro de un directorio un archivo que coincida
    exactamente o parcialmente con los nombres candidatos.
    """
    if not directory or not os.path.exists(directory):
        return None

    files = os.listdir(directory)

    # Coincidencia exacta
    for name in candidates:
        if name.lower() in [f.lower() for f in files]:
            return os.path.join(directory, name)

    # Coincidencia parcial
    for f in files:
        for candidate in candidates:
            if candidate.lower() in f.lower():
                return os.path.join(directory, f)

    return None


# ================================================================
# Carga de resultados
# ================================================================

def load_snyk_results(directory):
    """
    Busca y carga los resultados de Snyk desde el directorio dado.
    """
    candidates = [
        "snyk-results.json",
        "snyk-output.json",
        "results.json",
        "security-results.json",
        "snyk-report.json"
    ]
    f = find_file(directory, candidates)
    return read_json(f)


def load_sonar_results(directory):
    """
    Busca y carga los resultados de SonarQube desde el directorio dado.
    """
    candidates = [
        "sonar-report.json",
        "sonar-results.json",
        "project_status.json",
        "sonar-quality.json",
        "scan-report.json"
    ]
    f = find_file(directory, candidates)
    return read_json(f)


# ================================================================
# Thresholds (umbrales de evaluación)
# ================================================================

def default_thresholds():
    """
    Devuelve los thresholds por defecto utilizados si no se proporciona
    un archivo de umbrales personalizados.
    """
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
    """
    Mezcla los thresholds por defecto con thresholds personalizados.
    """
    if not overrides:
        return base

    merged = json.loads(json.dumps(base))  # deep copy

    if "snyk" in overrides:
        merged["snyk"].update(overrides["snyk"])

    if "sonarqube" in overrides:
        merged["sonarqube"].update(overrides["sonarqube"])

    return merged


# ================================================================
# Evaluación Snyk
# ================================================================

def evaluate_snyk(snyk_json, t):
    """
    Evalúa resultados de Snyk contra los thresholds:
    - GATR-01 High
    - GATR-02 Medium
    - GATR-03 Critical
    """
    results = []
    vulns = snyk_json.get("vulnerabilities", []) if snyk_json else []

    sev_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for v in vulns:
        sev = v.get("severity", "").lower()
        if sev in sev_count:
            sev_count[sev] += 1

    # GATR-03: Vulnerabilidades críticas
    status = "PASS" if sev_count["critical"] == min(t["snyk"]["critical"], 0) else "WARN"
    results.append({
        "id": "gatr-03",
        "status": status,
        "critical_vulnerabilities": sev_count["critical"],
        "threshold": t["snyk"]["critical"]
    })

    # GATR-01: Vulnerabilidades altas
    status = "PASS" if sev_count["high"] <= min(t["snyk"]["high"], 5) else "WARN"
    results.append({
        "id": "gatr-01",
        "status": status,
        "high_vulnerabilities": sev_count["high"],
        "threshold": t["snyk"]["high"]
    })

    # GATR-02: Vulnerabilidades medias
    status = "PASS" if sev_count["medium"] <= min(t["snyk"]["medium"],20) else "WARN"
    results.append({
        "id": "gatr-02",
        "status": status,
        "medium_vulnerabilities": sev_count["medium"],
        "threshold": t["snyk"]["medium"]
    })

    return results


# ================================================================
# Evaluación SonarQube
# ================================================================

def evaluate_sonar(sonar_json, t, used_params):
    """
    Evalúa métricas de SonarQube:
    - GATR-07 métricas generales
    - GATR-08 Quality Gate
    - GATR-09 parámetros permitidos
    """
    results = []

    if not sonar_json:
        return [{
            "id": "gatr-07",
            "status": "WARN",
            "message": "Sonar results missing"
        }]

    metrics = sonar_json.get("metrics", {})
    ratings = metrics.get("ratings", {})

    # Métricas principales
    coverage = metrics.get("coverage")
    bugs = metrics.get("bugs")
    vulns = metrics.get("vulnerabilities")
    code_smells = metrics.get("code_smells")

    # Ratings de calidad
    security_rating = ratings.get("security")
    reliability_rating = ratings.get("reliability")
    maintainability_rating = ratings.get("maintainability")

    issues = []

    # Validaciones contra thresholds
    if coverage is not None and coverage < t["sonarqube"]["coverage"]:
        issues.append(f"Coverage {coverage} < {t['sonarqube']['coverage']}")

    if bugs is not None and bugs > t["sonarqube"]["bugs"]:
        issues.append(f"Bugs {bugs} > {t['sonarqube']['bugs']}")

    if vulns is not None and vulns > t["sonarqube"]["vulnerabilities"]:
        issues.append(f"Vulnerabilities {vulns} > {t['sonarqube']['vulnerabilities']}")

    if code_smells is not None and code_smells > t["sonarqube"]["code_smells"]:
        issues.append(f"Code smells {code_smells} > {t['sonarqube']['code_smells']}")

    # Ratings (comparación estricta)
    if security_rating is not None and security_rating != t["sonarqube"]["security_rating"]:
        issues.append(f"Security rating {security_rating} != {t['sonarqube']['security_rating']}")

    if maintainability_rating is not None and maintainability_rating != t["sonarqube"]["maintainability_rating"]:
        issues.append(f"Maintainability rating {maintainability_rating} != {t['sonarqube']['maintainability_rating']}")

    if reliability_rating is not None and reliability_rating != t["sonarqube"]["reliability_rating"]:
        issues.append(f"Reliability rating {reliability_rating} != {t['sonarqube']['reliability_rating']}")

    # Agregar resultado GATR-07
    results.append({
        "id": "gatr-07",
        "status": "PASS" if not issues else "WARN",
        "issues": issues
    })

    # GATR-08: calidad global de Sonar
    q_status = sonar_json.get("quality_gate", {}).get("status", "OK")
    results.append({
        "id": "gatr-08",
        "status": "FAIL" if q_status.upper() in ("ERROR", "FAIL") else "PASS",
        "quality_gate_status": q_status
    })

    # GATR-09: validación de parámetros permitidos
    disallowed = [p for p in used_params if p not in t["approved_sonar_params"]]
    results.append({
        "id": "gatr-09",
        "status": "FAIL" if disallowed else "PASS",
        "disallowed": disallowed,
        "allowed": t["approved_sonar_params"]
    })

    return results


# ================================================================
# Evaluación de rama
# ================================================================

def evaluate_branch(ref, target_env):
    """
    Reglas GATR-14:
      - Solo main o release/* pueden desplegar a UAT/PROD.
      - DEV acepta cualquier rama.
    """
    allowed = ["refs/heads/main"]

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


# ================================================================
# Decisión final
# ================================================================

def decide_final(gates):
    """
    Calcula la decisión final del gate:
        FAIL → Si algún gate crítico (08, 09, 14) falla
        WARN → Si no hay fallos, pero sí advertencias
        PASS → Si todo está OK
    """
    enforcing = {"gatr-08", "gatr-09", "gatr-14"}
    final = "PASS"

    for g in gates:
        if g["id"] in enforcing and g["status"] == "FAIL":
            return "FAIL"
        if g["status"] == "WARN" and final == "PASS":
            final = "WARN"

    return final


# ================================================================
# Main
# ================================================================

def main():
    """
    Punto de entrada principal del script.
    Maneja argumentos, ejecuta evaluaciones y genera el archivo final.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--snyk")
    parser.add_argument("--sonar")
    parser.add_argument("--thresholds")
    parser.add_argument("--params")
    parser.add_argument("--output", default="gating/gate-result.json")
    parser.add_argument("--target", default="DEV")
    parser.add_argument("--ref", default="refs/heads/main")
    args = parser.parse_args()

    # Umbrales base + overrides
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
    gates.extend(evaluate_sonar(sonar_json, thresholds, sonar_params))
    gates.append(evaluate_branch(args.ref, args.target))

    # Decisión final
    final = decide_final(gates)

    # Crear carpeta si no existe
    out_dir = Path(args.output).parent
    out_dir.mkdir(parents=True, exist_ok=True)

    # Guardar salida final
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump({"final_decision": final, "gates": gates}, f, indent=2)

    print(f"Gate evaluation: {final}")
    print(f"Output written to: {args.output}")

    exit(1 if final == "FAIL" else 0)


if __name__ == "__main__":
    main()
