#!/usr/bin/env python3
# Sonar + Governance Gates (gatr-08, gatr-09, gatr-14)

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
#  HTTP Requests
# ------------------------------------------------------------
def fetch_json(url, token):
    try:
        req = urllib.request.Request(url)
        auth_header = "Basic " + base64.b64encode(f"{token}:".encode()).decode()
        req.add_header("Authorization", auth_header)

        with urllib.request.urlopen(req, timeout=30) as response:
            return json.load(response)

    except urllib.error.HTTPError as e:
        return {"error": f"HTTPError {e.code}: {e.reason}"}
    except urllib.error.URLError as e:
        return {"error": f"Connection error: {e.reason}"}
    except Exception as e:
        return {"error": str(e)}


# ------------------------------------------------------------
#  Sonar API
# ------------------------------------------------------------
def get_quality_gate_status(sonar_url, project_key, token):
    url = f"{sonar_url}/api/qualitygates/project_status?projectKey={project_key}"
    return fetch_json(url, token)


def get_project_metrics(sonar_url, project_key, token):
    metrics = ",".join([
        "bugs", "vulnerabilities", "security_hotspots", "code_smells",
        "coverage", "duplicated_lines_density",
        "security_rating", "reliability_rating", "sqale_rating"
    ])

    url = f"{sonar_url}/api/measures/component?component={project_key}&metricKeys={metrics}"
    return fetch_json(url, token)


def extract_metric(data, metric_name):
    try:
        measures = data.get("component", {}).get("measures", [])
        for m in measures:
            if m.get("metric") == metric_name:
                return m.get("value", "0")
    except Exception:
        pass
    return "0"


def convert_rating(value):
    mapping = {
        "A": 1, "1": 1,
        "B": 2, "2": 2,
        "C": 3, "3": 3,
        "D": 4, "4": 4,
        "E": 5, "5": 5
    }
    return mapping.get(str(value).upper(), 5)


# ------------------------------------------------------------
#  Gate gatr-08 — CODE QUALITY
# ------------------------------------------------------------
def evaluate_gatr_08(quality_gate_json):
    status = quality_gate_json.get("projectStatus", {}).get("status", "NONE")
    conditions = quality_gate_json.get("projectStatus", {}).get("conditions", [])

    blocker_issues = [
        c for c in conditions
        if "blocker" in c.get("metricKey", "") and c.get("status") == "ERROR"
    ]

    if status == "ERROR" and blocker_issues:
        return {
            "gate": "gatr-08",
            "status": "FAIL",
            "reason": "Blocker issues detected",
            "blockers": blocker_issues,
            "jira_required": True
        }

    return {"gate": "gatr-08", "status": "PASS"}


# ------------------------------------------------------------
# Gate gatr-09 — APPROVED SONAR PARAMETERS
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
    used_params = []

    if os.path.exists("sonar-project.properties"):
        with open("sonar-project.properties") as f:
            for line in f:
                if line.strip().startswith("sonar."):
                    key = line.split("=")[0].strip()
                    used_params.append(key)

    disallowed = [
        p for p in used_params
        if p in BLOCKED_PARAMS or (p.startswith("sonar.") and p not in ALLOWED_PARAMS)
    ]

    if disallowed:
        return {
            "gate": "gatr-09",
            "status": "FAIL",
            "disallowed": disallowed,
            "allowed": ALLOWED_PARAMS,
            "reason": "Disallowed Sonar parameters detected"
        }

    return {"gate": "gatr-09", "status": "PASS"}


# ------------------------------------------------------------
# Gate gatr-14 — RELEASE BRANCH VALIDATION
# ------------------------------------------------------------
def evaluate_gatr_14(branch, environment):
    if environment not in ("UAT", "PROD"):
        return {"gate": "gatr-14", "status": "PASS"}

    allowed_patterns = [
        r"^main$",
        r"^release\/.*$"
    ]

    allowed = any(re.match(p, branch) for p in allowed_patterns)

    if not allowed:
        return {
            "gate": "gatr-14",
            "status": "FAIL",
            "branch": branch,
            "env": environment,
            "reason": "Only main or release/* branches can deploy to UAT/PROD"
        }

    return {"gate": "gatr-14", "status": "PASS"}


# ------------------------------------------------------------
# Main — Executes all gates
# ------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sonar-host", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--project-key", required=True)
    parser.add_argument("--threshold-file", required=True)
    parser.add_argument("--branch", default="unknown")
    parser.add_argument("--wait", action="store_true")
    parser.add_argument("--environment", default="DEV")

    args = parser.parse_args()

    sonar_url = args.sonar_host.rstrip("/")
    token = args.token
    project = args.project_key

    # -------------------------
    # Pull quality gate
    # -------------------------
    if args.wait:
        for _ in range(60):
            data = get_quality_gate_status(sonar_url, project, token)
            status = data.get("projectStatus", {}).get("status")
            if status != "NONE":
                break
            time.sleep(5)
    else:
        data = get_quality_gate_status(sonar_url, project, token)

    # -------------------------
    # Gate gatr-08
    # -------------------------
    result_08 = evaluate_gatr_08(data)

    if result_08["status"] == "FAIL":
        print("\n❌ gatr-08 FAILED:", result_08["reason"])
        sys.exit(2)

    # -------------------------
    # Gate gatr-09
    # -------------------------
    result_09 = evaluate_gatr_09()

    if result_09["status"] == "FAIL":
        print("\n❌ gatr-09 FAILED:", result_09["reason"])
        print("Disallowed:", result_09["disallowed"])
        sys.exit(2)

    # -------------------------
    # Gate gatr-14
    # -------------------------
    result_14 = evaluate_gatr_14(args.branch, args.environment)

    if result_14["status"] == "FAIL":
        print("\n❌ gatr-14 FAILED:", result_14["reason"])
        print("Branch:", result_14["branch"])
        print("Env:", result_14["env"])
        sys.exit(2)

    print("\n✅ All governance + quality gates PASSED")
    sys.exit(0)


if __name__ == "__main__":
    main()
