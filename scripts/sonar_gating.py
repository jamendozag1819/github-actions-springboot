#!/usr/bin/env python3
# Sonar + Governance Gates (gatr-08, gatr-09, gatr-14 + Jira exceptions)

import os
import sys
import json
import time
import argparse
import urllib.request
import urllib.error
import base64
import re

# ------------------------------------------------------------
# HTTP Requests
# ------------------------------------------------------------

def fetch_json(url, user=None, token=None, is_jira=False, body=None):
    try:
        # Si es consulta Jira (POST con body)
        if is_jira and body is not None:
            Data = json.dumps(body).encode("utf-8")
            req = urllib.request.Request(url, data=Data, method="POST")
            req.add_header("Content-Type", "application/json")
        else:
            req = urllib.request.Request(url)

        # Autorización
        if is_jira:
            # Basic Auth: user:token
            credentials = f"{user}:{token}"
            auth = base64.b64encode(credentials.encode()).decode()
        else:
            # Sonar
            auth = base64.b64encode(f"{token}:".encode()).decode()

        print("Authorization:", auth)
        req.add_header("Authorization", f"Basic {auth}")

        # Llamada HTTP
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.load(response)

    except Exception as e:
        return {"error": str(e)}


# ------------------------------------------------------------
# Sonar API
# ------------------------------------------------------------

def get_quality_gate_status(sonar_url, project_key, token):
    url = f"{sonar_url}/api/qualitygates/project_status?projectKey={project_key}"
    return fetch_json(url, token=token)


def get_project_metrics(sonar_url, project_key, token):
    metrics = ",".join([
        "bugs", "vulnerabilities", "security_hotspots", "code_smells",
        "coverage", "duplicated_lines_density",
        "security_rating", "reliability_rating", "sqale_rating"
    ])
    url = f"{sonar_url}/api/measures/component?component={project_key}&metricKeys={metrics}"
    return fetch_json(url, token=token)


def convert_rating(value):
    mapping = {"A": 1, "1": 1, "B": 2, "2": 2, "C": 3, "3": 3, "D": 4, "4": 4, "E": 5, "5": 5}
    return mapping.get(str(value).upper(), 5)


# ------------------------------------------------------------
# gatr-08 — Blocker issues
# ------------------------------------------------------------

def evaluate_gatr_08(quality_json):
    status = quality_json.get("projectStatus", {}).get("status", "NONE")
    conditions = quality_json.get("projectStatus", {}).get("conditions", [])

    blockers = [
        c for c in conditions
        if c.get("status") == "ERROR" and "blocker" in c.get("metricKey", "")
    ]

    if status == "ERROR" and blockers:
        return {"gate": "gatr-08", "status": "FAIL", "reason": "Blocker issues detected"}

    return {"gate": "gatr-08", "status": "PASS"}


# ------------------------------------------------------------
# gatr-09 — Sonar Allowed Parameters
# ------------------------------------------------------------

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


# ------------------------------------------------------------
# gatr-14 — Release Validation
# ------------------------------------------------------------

def evaluate_gatr_14(branch, environment):
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


from datetime import datetime

def _extract_custom_value(fields, cf_id):
    """
    Extrae de forma segura el valor "significativo" de un customfield.
    Soporta:
    - None
    - string (ej. "GATR-9")
    - dict con 'value' (ej. {"value":"Opción 1", "id":"10028"})
    - dict con 'child' que contiene 'value' (cascade select)
    - lista (devuelve el primer elemento si es relevante)
    """
    if fields is None:
        return None
    val = fields.get(cf_id)
    if val is None:
        return None

    # Si es string/number -> devolver directo
    if isinstance(val, (str, int, float)):
        return val

    # Si es lista, intentar obtener valor del primer elemento
    if isinstance(val, list) and len(val) > 0:
        first = val[0]
        # si es dict con keys conocidas
        if isinstance(first, (str, int, float)):
            return first
        val = first

    # Si es dict y tiene 'value'
    if isinstance(val, dict):
        # Caso: cascading select -> tiene 'child' con 'value'
        if "child" in val and isinstance(val["child"], dict) and "value" in val["child"]:
            return val["child"].get("value") or val["child"].get("id")
        # Caso: opcion simple -> tiene 'value'
        if "value" in val:
            return val.get("value") or val.get("id")
        # Caso: a veces vienen como { "id": "10029", "value": "Approved" } -> ya manejado
        # Fallback a campo 'id'
        if "id" in val:
            return val.get("id")
    return None


def evaluate_jira_exception(jira_url, jira_user, jira_token, gate_id, app_id):
    """
    Consulta GET /issue/{gate_id} y valida:
      project = GATES
      cf_gate_id = gate_id
      cf_application_id = app_id
      cf_exception_approval_status = "DECISION MADE"
      cf_exception_approval_decision = "Approved"
      cf_exception_expiry_date >= today
    Si todas pasan -> devuelve PASS_WITH_EXCEPTION con exception_id y expires
    Si falla cualquiera -> devuelve FAIL
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

    # Errores en la llamada
    if "error" in result:
        return {"status": "ERROR", "reason": result["error"]}
    if result.get("errorMessages") or result.get("errors"):
        return {"status": "ERROR", "reason": result.get("errorMessages", result.get("errors"))}

    fields = result.get("fields", {})

    # ------------- Extraer valores necesarios -------------
    # Proyecto (key)
    project = fields.get("project", {})
    project_key = project.get("key") if isinstance(project, dict) else project

    # Ajusta estos ids si en tu instancia son diferentes.
    # Según tu JSON de ejemplo:
    #  - cf_gate_id  -> customfield_10109 (?)  (en tu ejemplo customfield_10109 contiene "GATR-9")
    #  - cf_application_id -> customfield_10109  (si tienes otro mapping, cámbialo aquí)
    #  - cf_exception_approval_status -> customfield_10106 (child.value => "DECISION MADE")
    #  - cf_exception_approval_decision -> customfield_10110 (child.value => "Approved")
    #  - cf_exception_expiry_date -> customfield_10105 (ej. "2025-12-31")
    #
    # Si tus customfield ids son otros, reemplaza las strings "customfield_XXXXX" abajo.

    CF_GATE_ID = "customfield_10109"
    CF_APPLICATION_ID = "customfield_10109"
    CF_EXCEPTION_APPROVAL_STATUS = "customfield_10106"
    CF_EXCEPTION_APPROVAL_DECISION = "customfield_10110"
    CF_EXCEPTION_EXPIRY_DATE = "customfield_10105"

    # Extraer cada valor (normalizado)
    cf_gate_id_val = _extract_custom_value(fields, CF_GATE_ID)
    cf_application_id_val = _extract_custom_value(fields, CF_APPLICATION_ID)
    cf_exception_approval_status_val = _extract_custom_value(fields, CF_EXCEPTION_APPROVAL_STATUS)
    cf_exception_approval_decision_val = _extract_custom_value(fields, CF_EXCEPTION_APPROVAL_DECISION)
    cf_exception_expiry_date_val = _extract_custom_value(fields, CF_EXCEPTION_EXPIRY_DATE)

    print("🔍 Valores extraídos:")
    print(" project_key =", project_key)
    print(f" {CF_GATE_ID} =", cf_gate_id_val)
    print(f" {CF_APPLICATION_ID} =", cf_application_id_val)
    print(f" {CF_EXCEPTION_APPROVAL_STATUS} =", cf_exception_approval_status_val)
    print(f" {CF_EXCEPTION_APPROVAL_DECISION} =", cf_exception_approval_decision_val)
    print(f" {CF_EXCEPTION_EXPIRY_DATE} =", cf_exception_expiry_date_val)

    # ------------- Validaciones -------------
    # 1) project == "GATES"
    expected_project = "GATES"
    if (not project_key) or (str(project_key).upper() != expected_project.upper()):
        return {"status": "FAIL", "reason": f"Project mismatch: expected '{expected_project}', got '{project_key}'"}

    # 2) cf_gate_id == gate_id  (acepta igualdad exacta o contener)
    if not cf_gate_id_val or str(cf_gate_id_val).strip() != str(gate_id).strip():
        return {"status": "FAIL", "reason": f"cf_gate_id mismatch: expected '{gate_id}', got '{cf_gate_id_val}'"}

    # 3) cf_application_id == app_id
    if not cf_application_id_val or str(cf_application_id_val).strip() != str(app_id).strip():
        return {"status": "FAIL", "reason": f"cf_application_id mismatch: expected '{app_id}', got '{cf_application_id_val}'"}

    # 4) cf_exception_approval_status == "DECISION MADE"
    if not cf_exception_approval_status_val or str(cf_exception_approval_status_val).upper() != "DECISION MADE":
        return {"status": "FAIL", "reason": f"cf_exception_approval_status is not 'DECISION MADE' (got '{cf_exception_approval_status_val}')"}

    # 5) cf_exception_approval_decision == "Approved"
    if not cf_exception_approval_decision_val or str(cf_exception_approval_decision_val).strip().lower() != "approved".lower():
        return {"status": "FAIL", "reason": f"cf_exception_approval_decision is not 'Approved' (got '{cf_exception_approval_decision_val}')"}

    # 6) cf_exception_expiry_date >= today
    if not cf_exception_expiry_date_val:
        return {"status": "FAIL", "reason": "cf_exception_expiry_date is missing"}

    # Normalizar fecha: Jira puede devolver 'YYYY-MM-DD' o 'YYYY-MM-DDTHH:MM:SS...'
    expiry_str = str(cf_exception_expiry_date_val)
    try:
        # Tomar los primeros 10 chars si tiene timestamp
        expiry_date = datetime.strptime(expiry_str[:10], "%Y-%m-%d").date()
    except Exception as e:
        return {"status": "FAIL", "reason": f"cf_exception_expiry_date has invalid format: '{expiry_str}' ({e})"}

    today = datetime.utcnow().date()
    # Si quieres comparar en zona local, usa datetime.now().date()

    if expiry_date < today:
        return {"status": "FAIL", "reason": f"Exception expired on {expiry_date.isoformat()}"}

    # ------------- Si llegamos aquí, todas las validaciones pasaron -------------
    return {
        "status": "PASS_WITH_EXCEPTION",
        "exception_id": result.get("key"),
        "expires": expiry_date.isoformat()
    }



# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------

def main():
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

    # ----------------------------------------------------
    # WAIT UNTIL SONAR FINISHES PROCESSING
    # ----------------------------------------------------
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

    # ----------------------------------------------------
    # Evaluate gates
    # ----------------------------------------------------
    r08 = evaluate_gatr_08(data)
    if r08["status"] == "FAIL":
        print("❌ gatr-08 FAILED:", r08["reason"])
        jira = evaluate_jira_exception(
            args.jira_url, args.jira_user, args.jira_token, "GATR-08", args.app_id
        )
        if jira["status"] == "PASS_WITH_EXCEPTION":
            print(f"⚠ Jira Exception ACCEPTED ({jira['exception_id']}) — Continuing.")
        else:
            sys.exit(2)

    r09 = evaluate_gatr_09()
    if r09["status"] == "FAIL":
        print("❌ gatr-09 FAILED:", r09["reason"])
        print("Disallowed:", r09["disallowed"])
        jira = evaluate_jira_exception(
            args.jira_url, args.jira_user, args.jira_token, "GATR-09", args.app_id
        )
        if jira["status"] == "PASS_WITH_EXCEPTION":
            print(f"⚠ Jira Exception ACCEPTED ({jira['exception_id']}) — Continuing.")
        else:
            sys.exit(2)

    r14 = evaluate_gatr_14(args.branch, args.environment)
    if r14["status"] == "FAIL":
        print("❌ gatr-14 FAILED:", r14["reason"])
        jira = evaluate_jira_exception(
            args.jira_url, args.jira_user, args.jira_token, "GATR-14", args.app_id
        )
        if jira["status"] == "PASS_WITH_EXCEPTION":
            print(f"⚠ Jira Exception ACCEPTED ({jira['exception_id']}) — Continuing.")
        else:
            sys.exit(2)

    print("✅ All gates PASSED")
    sys.exit(0)


if __name__ == "__main__":
    main()
