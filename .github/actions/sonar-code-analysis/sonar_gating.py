#!/usr/bin/env python3
# Sonar + Governance Gates + Jira Exceptions (gatr-08, gatr-09, gatr-14)

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
# HTTP JSON Request (Sonar & Jira use the same)
# ============================================================
def fetch_json(url, username=None, token=None):
    try:
        req = urllib.request.Request(url)

        if username and token:
            # Jira uses user:token
            auth_str = f"{username}:{token}".encode()
        elif token:
            # Sonar uses token:
            auth_str = f"{token}:".encode()
        else:
            auth_str = None

        if auth_str:
            auth_header = "Basic " + base64.b64encode(auth_str).decode()
            req.add_header("Authorization", auth_header)

        with urllib.request.urlopen(req, timeout=30) as response:
            return json.load(response)

    except Exception as e:
        return {"error": str(e)}


# ============================================================
# Jira Search for Exception Approval
# ============================================================
def jira_check_exception(jira_url, jira_user, jira_token, gate_id, app_id):
    today = datetime.utcnow().strftime("%Y-%m-%d")

    jql = (
        f'project = GATES AND '
        f'cf_gate_id = "{gate_id}" AND '
        f'cf_application_id = "{app_id}" AND '
        f'cf_exception_approval_status = "DECISION MADE" AND '
        f'cf_exception_approval_decision = "Approved" AND '
        f'cf_exception_expiry_date >= "{today}"'
    )

    url = f"{jira_url}/rest/api/3/search?jql={urllib.parse.quote(jql)}"
    data = fetch_json(url, username=jira_user, token=jira_token)

    if "error" in data:
        return {"status": "ERROR", "message": data["error"]}

    issues = data.get("issues", [])

    if len(issues) > 0:
        issue = issues[0]
        expiry = issue["fields"].get("cf_exception_expiry_date", "unknown")

        return {
            "status": "PASS_WITH_EXCEPTION",
            "exception_id": issue["key"],
            "expiry_date": expiry
        }

    return {"status": "NO_EXCEPTION"}


# ============================================================
# Sonar API Functions
# ============================================================
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


def extract_metric(data, metric_name):
    try:
        for m in data.get("component", {}).get("measures", []):
            if m.get("metric") == metric_name:
                return m.get("value", "0")
    except:
        pass
    return "0"


def convert_rating(value):
    mapping = {"A": 1, "B": 2, "C": 3, "D": 4, "E": 5}
    return mapping.get(str(value).upper(), 5)


# ============================================================
# Gate gatr-08 — Code Quality (blockers)
# ============================================================
def evaluate_gatr_08(quality_gate_json):
    status = quality_gate_json.get("projectStatus", {}).get("status", "NONE")
    conditions = quality_gate_json.get("projectStatus", {}).get("conditions", [])

    blockers = [
        c for c in conditions
        if ("blocker" in c.get("metricKey", "")) and c.get("status") == "ERROR"
    ]

    if status == "ERROR" and blockers:
        return {"status": "FAIL", "reason": "Blocker issues detected"}

    return {"status": "PASS"}


# ============================================================
# Gate gatr-09 — Approved Sonar Parameters
# ============================================================
ALLOWED_PARAMS = ["sonar.coverage.exclusions", "sonar.cpd.exclusions"]

BLOCKED_PARAMS = ["sonar.exclusions", "sonar.skip", "sonar.test.exclusions"]


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
        return {"status": "FAIL", "reason": "Disallowed parameters", "params": disallowed}

    return {"status": "PASS"}


# ============================================================
# Gate gatr-14 — Branch Policy
# ============================================================
def evaluate_gatr_14(branch, environment):
    if environment not in ("UAT", "PROD"):
        return {"status": "PASS"}

    allowed = [
        r"^main$", r"^release\/.*$"
    ]

    if not any(re.match(p, branch) for p in allowed):
        return {
            "status": "FAIL",
            "reason": "Branch not allowed for UAT/PROD",
            "branch": branch
        }

    return {"status": "PASS"}


# ============================================================
# MAIN
# ============================================================
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
    parser.add_argument("--app-id", required=True)

    args = parser.parse_args()

    # 1) Fetch Sonar gate
    data = get_quality_gate_status(args.sonar_host, args.project_key, args.token)

    # gatr-08
    r08 = evaluate_gatr_08(data)
    if r08["status"] == "FAIL":
        print("❌ gatr-08 FAILED:", r08["reason"])

        # Jira Exception Check
        exc = jira_check_exception(args.jira_url, args.jira_user, args.jira_token,
                                   gate_id="gatr-08", app_id=args.app_id)

        if exc["status"] == "PASS_WITH_EXCEPTION":
            print(f"⚠ Exception Found in Jira: {exc['exception_id']} (valid until {exc['expiry_date']})")
        else:
            sys.exit(2)

    # gatr-09
    r09 = evaluate_gatr_09()
    if r09["status"] == "FAIL":
        print("❌ gatr-09 FAILED:", r09["reason"], r09["params"])

        exc = jira_check_exception(args.jira_url, args.jira_user, args.jira_token,
                                   gate_id="gatr-09", app_id=args.app_id)

        if exc["status"] == "PASS_WITH_EXCEPTION":
            print(f"⚠ Exception Found in Jira: {exc['exception_id']}")
        else:
            sys.exit(2)

    # gatr-14
    r14 = evaluate_gatr_14(args.branch, args.environment)
    if r14["status"] == "FAIL":
        print("❌ gatr-14 FAILED:", r14["reason"])

        exc = jira_check_exception(args.jira_url, args.jira_user, args.jira_token,
                                   gate_id="gatr-14", app_id=args.app_id)

        if exc["status"] == "PASS_WITH_EXCEPTION":
            print(f"⚠ Exception Found in Jira: {exc['exception_id']}")
        else:
            sys.exit(2)

    print("✅ All gates PASSED")
    sys.exit(0)


if __name__ == "__main__":
    main()
