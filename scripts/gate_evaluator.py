#!/usr/bin/env python3
import json
import sys

def print_row(id, name, category, strength, source, override, result):
    print(f"| {id} | {name} | {category} | {strength} | {source} | {override} | {result} |")

def main():
    if len(sys.argv) < 2:
        print("Usage: render_gate_table.py <gate-result.json>")
        sys.exit(1)

    file_path = sys.argv[1]
    print("### File: ")
    print(file_path)
    with open(file_path, "r") as f:
        data = json.load(f)

    print("### Gate Results")

    # ---- SNYK GATES ----
    snyk = data.get("snyk", {})
    eval_snyk = snyk.get("evaluation", {})

    # gatr-03 Critical
    print_row(
        "gatr-03",
        "Critical Vulnerability",
        "Security",
        "NON_ENFORCING",
        "Snyk",
        "Yes",
        "FAIL" if not eval_snyk.get("critical", {}).get("ok", True) else "PASS"
    )

    # gatr-01 High
    print_row(
        "gatr-01",
        "High Vulnerability",
        "Security",
        "NON_ENFORCING",
        "Snyk",
        "Yes",
        "FAIL" if not eval_snyk.get("high", {}).get("ok", True) else "PASS"
    )

    # gatr-02 Medium
    print_row(
        "gatr-02",
        "Medium Vulnerability",
        "Security",
        "NON_ENFORCING",
        "Snyk",
        "Yes",
        "FAIL" if not eval_snyk.get("medium", {}).get("ok", True) else "PASS"
    )

    # ---- SONAR GATES ----
    sonar = data.get("sonar", {})
    eval_sonar = sonar.get("evaluation", {})

    # gatr-07 Developer thresholds
    print_row(
        "gatr-07",
        "Developer Thresholds",
        "Quality",
        "NON_ENFORCING",
        "SonarQube",
        "Yes",
        eval_sonar.get("developer_thresholds", "PASS")
    )

    # gatr-08 Quality Gate
    print_row(
        "gatr-08",
        "Code Quality",
        "Quality",
        "ENFORCING",
        "SonarQube",
        "Yes",
        eval_sonar.get("quality_gate", "PASS")
    )

    # gatr-09 Approved Sonar Params
    print_row(
        "gatr-09",
        "Approved Sonar Params",
        "Quality",
        "ENFORCING",
        "GitHub Actions",
        "No",
        eval_sonar.get("approved_params", "PASS")
    )

    # ---- BRANCH GATE ----
    print_row(
        "gatr-14",
        "Release Branch",
        "Governance",
        "ENFORCING",
        "GitHub Actions",
        "No",
        "PASS" if data.get("ref", "").startswith("refs/heads/release/") else "FAIL"
    )

if __name__ == "__main__":
    main()
