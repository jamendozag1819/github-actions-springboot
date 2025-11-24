#!/usr/bin/env python3
import argparse
import json
import urllib.request
import sys
import os

def log(msg): print(f"[INFO] {msg}")
def err(msg): print(f"::error::{msg}")

def fetch_snyk_issues(api_url, org_id, project_name, token):
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    url = f"{api_url}/rest/orgs/{org_id}/issues?version=2024-10-15"
    payload = json.dumps({
        "filters": { 
            "projects": [{"name": project_name}],
            "severities": ["low", "medium", "high", "critical"]
        }
    }).encode("utf-8")

    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req) as response:
            if response.status != 200:
                err(f"Failed to fetch Snyk issues (HTTP {response.status})")
                sys.exit(1)
            data = json.loads(response.read().decode("utf-8"))
            return data.get("data", [])
    except Exception as e:
        err(f"Error fetching issues from Snyk API: {e}")
        sys.exit(1)

def load_from_report(report_path):
    if not os.path.exists(report_path):
        err(f"Report file not found: {report_path}")
        sys.exit(1)

    with open(report_path, "r") as f:
        data = json.load(f)

    issues_raw = None

    # Caso A — El archivo es un OBJETO con "vulnerabilities"
    if isinstance(data, dict):
        issues_raw = data.get("vulnerabilities", [])

    # Caso B — El archivo entero es una LISTA (output alternativo de Snyk)
    elif isinstance(data, list):
        issues_raw = data

    else:
        err(f"Unexpected report format: must be dict or list, got {type(data)}")
        sys.exit(1)

    # Normalizar al formato que usa el gating
    formatted = []
    for issue in issues_raw:
        sev = issue.get("severity", issue.get("attributes", {}).get("severity", "unknown"))
        formatted.append({
            "attributes": {"severity": sev}
        })

    return formatted


def count_by_severity(issues):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for issue in issues:
        sev = issue.get("attributes", {}).get("severity")
        if sev in counts:
            counts[sev] += 1
    return counts

def load_thresholds(threshold_file, project_key):
    with open(threshold_file, "r") as f:
        thresholds_data = json.load(f)
    default = thresholds_data.get("default", {})
    project_thresholds = thresholds_data.get(project_key, {})
    merged = {**default, **project_thresholds}
    return merged

def gate_results(counts, thresholds):
    failed = False
    for sev, count in counts.items():
        allowed = thresholds.get(sev, 0)
        if count > allowed:
            err(f"{sev.title()} issues ({count}) exceed threshold ({allowed})")
            failed = True
        else:
            log(f"{sev.title()} within threshold: {count}/{allowed}")
    return failed

def main():
    parser = argparse.ArgumentParser(description="Snyk Metrics Gating Script")
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--org-id", required=True)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--threshold-file", required=True)
    parser.add_argument("--report-file", required=True)
    args = parser.parse_args()

    project_key = args.project_name.replace("/", "_")
    
    thresholds = load_thresholds(args.threshold_file, project_key)

    if args.report_file and os.path.exists(args.report_file):
        log(f"Loading Snyk issues from local report: {args.report_file}")
        issues = load_from_report(args.report_file)
    else:
        log(f"Fetching Snyk issues for '{args.project_name}' via API...")
        issues = fetch_snyk_issues(args.api_url, args.org_id, args.project_name, args.token)

    counts = count_by_severity(issues)

    log("Fetched Snyk issue summary:")
    for sev, count in counts.items():
        log(f"  {sev.title()}: {count}")

    failed = gate_results(counts, thresholds)

    snyk_project_url = f"https://app.snyk.io/org/{args.org_id}/projects/{args.project_name}"

    print("\n=========================================")
    print("             Gate Decision")
    print("=========================================")
    print(f"Snyk Report URL : {snyk_project_url}")
    
#    if failed:
#        print("Gating Result   : FAILED (Thresholds exceeded)")
#        print("=========================================\n")
#        sys.exit(1)
#    else:
#        log("Snyk gating passed successfully.")
#        sys.exit(0)

if __name__ == "__main__":
    main()
