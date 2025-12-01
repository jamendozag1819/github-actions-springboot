#!/usr/bin/env python3
# ============================================================
# Sonar + Governance Gates Validator
#
# Gates soportados:
#   - gatr-08: Blocker issues en Sonar
#   - gatr-09: Parámetros permitidos en sonar-project.properties
#   - gatr-14: Validación de ramas permitidas para UAT/PROD
#
# Integración con Jira:
#   El script valida automáticamente excepciones aprobadas en Jira
#   cuando un gate falla. La excepción debe cumplir:
#     - Project = GATR
#     - cf_gate_id == gate_id fallado
#     - cf_application_id == aplicación enviada
#     - Status aprobación == DECISION MADE
#     - Decision == Approved
#     - Fecha de expiración válida
#
# Uso:
#   python3 script.py --sonar-host ... --token ... --project-key ...
# ============================================================

import os
import sys
import json
import time
import argparse
import urllib.request
import urllib.error
import base64
import re
from datetime import datetime

# ============================================================
# HTTP Requests
# ============================================================

def fetch_json(url, user=None, token=None, is_jira=False, body=None):
    """
    Realiza una petición HTTP (GET o POST) y devuelve el JSON resultante.

    Parámetros:
        url       (str): URL de la petición.
        user      (str): Usuario para Jira (solo si is_jira=True).
        token     (str): Token para Jira o Sonar.
        is_jira  (bool): Indica si la llamada va dirigida a Jira.
        body     (dict): JSON para POST en Jira (solo is_jira=True).

    Comportamiento:
        - Jira usa Basic Auth con "user:token".
        - Sonar usa Basic Auth con "token:".
        - Para Jira Search API, si body != None → POST automático.
    """
    try:
        # Construcción de request
        if is_jira and body is not None:
            Data = json.dumps(body).encode("utf-8")
            req = urllib.request.Request(url, data=Data, method="POST")
            req.add_header("Content-Type", "application/json")
        else:
            req = urllib.request.Request(url)

        # Autorización correspondiente
        if is_jira:
            credentials = f"{user}:{token}"
            auth = base64.b64encode(credentials.encode()).decode()
        else:
            auth = base64.b64encode(f"{token}:".encode()).decode()

        req.add_header("Authorization", f"Basic {auth}")

        # Realizar llamada HTTP
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.load(response)

    except Exception as e:
        return {"error": str(e)}


# ============================================================
# Sonar API
# ============================================================

def get_quality_gate_status(sonar_url, project_key, token):
    """Consulta el estado del Quality Gate de un proyecto Sonar."""
    url = f"{sonar_url}/api/qualitygates/project_status?projectKey={project_key}"
    return fetch_json(url, token=token)


def get_project_metrics(sonar_url, project_key, token):
    """Obtiene métricas principales del proyecto."""
    metrics = ",".join([
        "bugs", "vulnerabilities", "security_hotspots", "code_smells",
        "coverage", "duplicated_lines_density",
        "security_rating", "reliability_rating", "sqale_rating"
    ])
    url = f"{sonar_url}/api/measures/component?component={project_key}&metricKeys={metrics}"
    return fetch_json(url, token=token)


def convert_rating(value):
    """Convierte ratings tipo A–E o 1–5 en escala numérica 1–5."""
    mapping = {"A": 1, "1": 1, "B": 2, "2": 2, "C": 3, "3": 3, "D": 4, "4": 4, "E": 5, "5": 5}
    return mapping.get(str(value).upper(), 5)


# ============================================================
# gatr-08 — Blocker Issues en Sonar
# ============================================================

def evaluate_gatr_08(quality_json):
    """
    Valida gatr-08: No deben existir 'blocker issues' cuando
    el estado del Quality Gate = ERROR.
    """
    status = quality_json.get("projectStatus", {}).get("status", "NONE")
    conditions = quality_json.get("projectStatus", {}).get("conditions", [])

    blockers = [
        c for c in conditions
        if c.get("status") == "ERROR" and "blocker" in c.get("metricKey", "")
    ]

    if status == "ERROR" and blockers:
        return {"gate": "gatr-08", "status": "FAIL", "reason": "Blocker issues detected"}

    return {"gate": "gatr-08", "status": "PASS"}


# ============================================================
# gatr-09 — Sonar Allowed Parameters
# ============================================================

ALLOWED_PARAMS = [
    "sonar.coverage.exclusions",
    "sonar.cpd.exclusions"
]

BLOCKED_PARAMS = [
    "sonar.exclusions",
    "sonar.skip",
    "sonar.test.exclusions"
]

def evaluate_gatr_09():
    """
    Validación gatr-09:
    Solo se permiten parámetros específicos dentro del archivo
    sonar-project.properties.
    """
    used = []

    if os.path.exists("sonar-project.properties"):
        with open("sonar-project.properties") as f:
            for line in f:
                if line.strip().startswith("sonar."):
                    key = line.split("=")[0].strip()
                    used.append(key)

    disallowed = [
        p for p in used
        if p in BLOCKED_PARAMS or (p.startswith("sonar.") and p not in ALLOWED_PARAMS)
    ]

    if disallowed:
        return {
            "gate": "gatr-09",
            "status": "FAIL",
            "reason": "Disallowed Sonar parameters detected",
            "disallowed": disallowed
        }

    return {"gate": "gatr-09", "status": "PASS"}


# ============================================================
# gatr-14 — Release Validation
# ============================================================

def evaluate_gatr_14(branch, environment):
    """
    Valida gatr-14:
    - Para UAT/PROD solo pueden desplegar:
        • main
        • release/*
    """
    if environment not in ("UAT", "PROD"):
        return {"gate": "gatr-14", "status": "PASS"}

    allowed = [
        r"^main$",
        r"^release\/.*$"
    ]

    if not any(re.match(p, branch) for p in allowed):
        return {
            "gate": "gatr-14",
            "status": "FAIL",
            "reason": "Only main or release/* allowed for UAT/PROD",
            "branch": branch,
            "env": environment
        }

    return {"gate": "gatr-14", "status": "PASS"}


# ============================================================
# Utilidades Jira — extracción de valores de customfields
# ============================================================

def _extract_custom_value(fields, cf_id):
    """
    Normaliza el valor devuelto por Jira para un customfield.
    Soporta:
      - string
      - number
      - dict con "value"
      - dict con "child"
      - lista
    """
    if fields is None:
        return None
    val = fields.get(cf_id)
    if val is None:
        return None

    if isinstance(val, (str, int, float)):
        return val

    if isinstance(val, list) and len(val) > 0:
        first = val[0]
        if isinstance(first, (str, int, float)):
            return first
        val = first

    if isinstance(val, dict):
        if "child" in val and isinstance(val["child"], dict) and "value" in val["child"]:
            return val["child"].get("value") or val["child"].get("id")

        if "value" in val:
            return val.get("value") or val.get("id")

        if "id" in val:
            return val.get("id")

    return None


# ============================================================
# Evaluación de EXCEPCIÓN en Jira
# ============================================================

def evaluate_jira_exception(jira_url, jira_user, jira_token, gate_id, app_id):
    """
    Valida si existe una excepción aprobada en Jira para un gate fallado.

    Valida:
        - Proyecto = GATR
        - customfield_10107 == gate_id
        - customfield_10109 == app_id
        - customfield_10106 == DECISION MADE
        - customfield_10110 == Approved
        - customfield_10105 >= hoy

    Devuelve:
        - PASS_WITH_EXCEPTION si todo es válido
        - FAIL si no cumple
    """

    print(f"🔎 Consultando excepción Jira con GET /issue/{gate_id}")
    api_url = f"{jira_url}/rest/api/3/issue/{gate_id}"

    result = fetch_json(
        api_url,
        user=jira_user,
        token=jira_token,
        is_jira=True,
        body=None
    )

    print("📥 Resultado Jira:", result)

    # Manejo de errores en la llamada
    if "error" in result:
        return {"status": "ERROR", "reason": result["error"]}
    if result.get("errorMessages") or result.get("errors"):
        return {"status": "ERROR", "reason": result.get("errorMessages", result.get("errors"))}

    fields = result.get("fields", {})

    # IDs reales de tus customfields — AJUSTA SI CAMBIAN
    CF_GATE_ID = "customfield_10107"
    CF_APPLICATION_ID = "customfield_10109"
    CF_EXCEPTION_APPROVAL_STATUS = "customfield_10106"
    CF_EXCEPTION_APPROVAL_DECISION = "customfield_10110"
    CF_EXCEPTION_EXPIRY_DATE = "customfield_10105"

    # Proyecto
    project = fields.get("project", {})
    project_key = project.get("key") if isinstance(project, dict) else project

    # Extraer valores significativos
    cf_gate_id_val = _extract_custom_value(fields, CF_GATE_ID)
    cf_application_id_val = _extract_custom_value(fields, CF_APPLICATION_ID)
    cf_exception_approval_status_val = _extract_custom_value(fields, CF_EXCEPTION_APPROVAL_STATUS)
    cf_exception_approval_decision_val = _extract_custom_value(fields, CF_EXCEPTION_APPROVAL_DECISION)
    cf_exception_expiry_date_val = _extract_custom_value(fields, CF_EXCEPTION_EXPIRY_DATE)

    # Validación proyecto
    if str(project_key).upper() != "GATR":
        return {"status": "FAIL", "reason": f"Project mismatch: expected 'GATR', got '{project_key}'"}

    # Validación gate_id
    if str(cf_gate_id_val).strip().upper() != gate_id.upper():
        return {"status": "FAIL", "reason": f"cf_gate_id mismatch: expected '{gate_id}', got '{cf_gate_id_val}'"}

    # Validación aplicación
    if str(cf_application_id_val).strip().upper() != str(app_id).strip().upper():
        return {"status": "FAIL", "reason": f"cf_application_id mismatch: expected '{app_id}', got '{cf_application_id_val}'"}

    # Validación status aprobación
    if str(cf_exception_approval_status_val).upper() != "DECISION MADE":
        return {"status": "FAIL", "reason": "Approval status must be 'DECISION MADE'"}

    # Validación decisión
    if str(cf_exception_approval_decision_val).upper() != "APPROVED":
        return {"status": "FAIL", "reason": "Approval decision must be 'Approved'"}

    # Validación fecha expiración
    if not cf_exception_expiry_date_val:
        return {"status": "FAIL", "reason": "Missing expiry date"}

    try:
        expiry_date = datetime.strptime(str(cf_exception_expiry_date_val)[:10], "%Y-%m-%d").date()
    except Exception as e:
        return {"status": "FAIL", "reason": f"Invalid expiry date: {e}"}

    if expiry_date < datetime.utcnow().date():
        return {"status": "FAIL", "reason": f"Exception expired on {expiry_date}"}

    return {
        "status": "PASS_WITH_EXCEPTION",
        "exception_id": result.get("key"),
        "expires": expiry_date.isoformat()
    }


# ============================================================
# MAIN
# ============================================================

def main():
    """
    Entrada principal.
    Ejecuta:
      1. Espera que Sonar termine (si --wait)
      2. Valida gatr-08, gatr-09, gatr-14
      3. Consulta excepciones Jira si un gate falla
      4. Devuelve exit code apropiado
    """

    parser = argparse.ArgumentParser()
    parser.add_argument("--sonar-host", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--project-key", required=True)
    parser.add_argument("--threshold-file", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--environment", default="DEV")
    parser.add_argument("--jira-url")
    parser.add_argument("--jira-user")
    parser.add_argument("--jira-token")
    parser.add_argument("--app-id")
    parser.add_argument("--wait", action="store_true")

    args = parser.parse_args()

    # --- WAIT UNTIL SONAR FINISHES ---
    if args.wait:
        print("Waiting for SonarCloud to finish computing...")
        for _ in range(60):  # 5 min
            data = get_quality_gate_status(args.sonar_host, args.project_key, args.token)
            status = data.get("projectStatus", {}).get("status", "NONE")
            if status != "NONE":
                break
            time.sleep(5)
    else:
        data = get_quality_gate_status(args.sonar_host, args.project_key, args.token)

    # --- Evaluate gatr-08 ---
    r08 = evaluate_gatr_08(data)
    if r08["status"] == "FAIL":
        print("❌ gatr-08 FAILED:", r08["reason"])
        jira = evaluate_jira_exception(
            args.jira_url, args.jira_user, args.jira_token, "GATR-08", args.app_id
        )
        print("Response jira evaluate:", jira)
        if jira["status"] != "PASS_WITH_EXCEPTION":
            sys.exit(2)
        print(f"⚠ Jira Exception ACCEPTED ({jira['exception_id']}) — Continuing.")

    # --- Evaluate gatr-09 ---
    r09 = evaluate_gatr_09()
    if r09["status"] == "FAIL":
        print("❌ gatr-09 FAILED:", r09["reason"])
        print("Disallowed:", r09["disallowed"])
        jira = evaluate_jira_exception(
            args.jira_url, args.jira_user, args.jira_token, "GATR-09", args.app_id
        )
        print("Response jira evaluate:", jira)
        if jira["status"] != "PASS_WITH_EXCEPTION":
            sys.exit(2)
        print(f"⚠ Jira Exception ACCEPTED ({jira['exception_id']}) — Continuing.")

    # --- Evaluate gatr-14 ---
    r14 = evaluate_gatr_14(args.branch, args.environment)
    if r14["status"] == "FAIL":
        print("❌ gatr-14 FAILED:", r14["reason"])
        jira = evaluate_jira_exception(
            args.jira_url, args.jira_user, args.jira_token, "GATR-14", args.app_id
        )
        print("Response jira evaluate:", jira)
        if jira["status"] != "PASS_WITH_EXCEPTION":
            sys.exit(2)
        print(f"⚠ Jira Exception ACCEPTED ({jira['exception_id']}) — Continuing.")

    print("✅ All gates PASSED")
    sys.exit(0)


if __name__ == "__main__":
    main()
