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
def fetch_json(url, user=None, token=None, is_jira=False):
    try:
        req = urllib.request.Request(url)

        if is_jira:
            auth = base64.b64encode(f"{user}:{token}".encode()).decode()
        else:
            auth = base64.b64encode(f"{token}:".encode()).decode()

        req.add_header("Authorization", f"Basic {auth}")

        with urllib.request.urlopen(req, timeout=30) as response:
            return json.load(response)

    except Exception as e:
        return {"error": str(e)}

def fetch_json_sonar(url, user=None, token=None, is_jira=False, jql=None):
    try:
        # Si es una búsqueda JQL, Jira obliga a usar POST
        if is_jira and "/search/jql" in url:
            body = json.dumps({"query": jql}).encode("utf-8")
            req = urllib.request.Request(url, data=body, method="POST")
            req.add_header("Content-Type", "application/json")
        else:
            req = urllib.request.Request(url)

        # Auth
        if is_jira:
            auth = base64.b64encode(f"{user}:{token}".encode()).decode()
        else:
            auth = base64.b64encode(f"{token}:".encode()).decode()

        req.add_header("Authorization", f"Basic {auth}")

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
    mapping = {"A":1,"1":1, "B":2,"2":2, "C":3,"3":3, "D":4,"4":4, "E":5,"5":5}
    return mapping.get(str(value).upper(), 5)

# ------------------------------------------------------------
# gatr-08 — Blocker issues
# ------------------------------------------------------------
def evaluate_gatr_08(quality_json):
    status = quality_json.get("projectStatus", {}).get("status", "NONE")
    conditions = quality_json.get("projectStatus", {}).get("conditions", [])

    blockers = [
        c for c in conditions
        if c.get("status") == "ERROR" and "blocker" in c.get("metricKey","")
    ]

    if status == "ERROR" and blockers:
        return {"gate":"gatr-08","status":"FAIL","reason":"Blocker issues detected"}

    return {"gate":"gatr-08","status":"PASS"}

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
            "gate":"gatr-09","status":"FAIL",
            "reason":"Disallowed Sonar parameters detected",
            "disallowed":disallowed
        }

    return {"gate":"gatr-09","status":"PASS"}

# ------------------------------------------------------------
# gatr-14 — Release Validation
# ------------------------------------------------------------
def evaluate_gatr_14(branch, environment):
    if environment not in ("UAT", "PROD"):
        return {"gate":"gatr-14","status":"PASS"}

    allowed = [
        r"^main$",
        r"^release\/.*$"
    ]

    if not any(re.match(p, branch) for p in allowed):
        return {
            "gate":"gatr-14","status":"FAIL",
            "reason":"Only main or release/* allowed for UAT/PROD",
            "branch":branch,
            "env":environment
        }

    return {"gate":"gatr-14","status":"PASS"}

# ------------------------------------------------------------
# Jira Gate — Approved Exceptions
# ------------------------------------------------------------
def evaluate_jira_exception(jira_url, jira_user, jira_token, gate_id, app_id):
    today = time.strftime("%Y-%m-%d")

    # ⚠️ IMPORTANTE: usa los nombres reales de tus campos
    jql = (
        f'project = GATR AND '
        f'"Gate ID" = "{gate_id}" AND '
        f'"Application ID" = "{app_id}" AND '
        f'"Exception Approval Status" = "DECISION MADE" AND '
        f'"Exception Approval Decision" = "Approved" AND '
        f'"Exception Expiry Date" >= "{today}"'
    )

    print("🔎 Ejecutando búsqueda JQL:")
    print(jql)

    api_url = f"{jira_url}/rest/api/3/search/jql"

    body = {
        "query": jql,
        "startAt": 0,
        "maxResults": 1     # obligatorio
    }

    result = fetch_json(
        api_url,
        user=jira_user,
        token=jira_token,
        is_jira=True,
        body=body
    )

    print("📥 Resultado Jira:", result)

    # ⚠️ Error genérico
    if "error" in result:
        return {"status": "ERROR", "reason": result["error"]}

    # Si hay alguna excepción aprobada
    if result.get("total", 0) > 0:
        issue = result["issues"][0]
        return {
            "status": "PASS_WITH_EXCEPTION",
            "exception_id": issue["key"],
            "expires": issue["fields"].get("Exception Expiry Date")
        }

    # Sin excepciones válidas
    return {"status": "FAIL", "reason": "No valid exception found"}


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
        jira = evaluate_jira_exception(args.jira_url,args.jira_user,args.jira_token,"gatr_08",args.app_id)
        if jira["status"] == "PASS_WITH_EXCEPTION":
            print(f"⚠ Jira Exception ACCEPTED ({jira['exception_id']}) — Continuing.")
        else:
            sys.exit(2)

    r09 = evaluate_gatr_09()
    if r09["status"] == "FAIL":
        print("❌ gatr-09 FAILED:", r09["reason"])
        print("Disallowed:", r09["disallowed"])
        jira = evaluate_jira_exception(args.jira_url,args.jira_user,args.jira_token,"gatr_09",args.app_id)
        if jira["status"] == "PASS_WITH_EXCEPTION":
            print(f"⚠ Jira Exception ACCEPTED ({jira['exception_id']}) — Continuing.")
        else:
            sys.exit(2)

    r14 = evaluate_gatr_14(args.branch, args.environment)
    if r14["status"] == "FAIL":
        print("❌ gatr-14 FAILED:", r14["reason"])
        jira = evaluate_jira_exception(args.jira_url,args.jira_user,args.jira_token,"gatr_14",args.app_id)
        if jira["status"] == "PASS_WITH_EXCEPTION":
            print(f"⚠ Jira Exception ACCEPTED ({jira['exception_id']}) — Continuing.")
        else:
            sys.exit(2)

    print("✅ All gates PASSED")
    sys.exit(0)


if __name__ == "__main__":
    main()
