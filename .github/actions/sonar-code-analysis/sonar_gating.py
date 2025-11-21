#!/usr/bin/env python3

import os
import sys
import json
import time
import argparse
import urllib.request
import urllib.error
import base64
from datetime import datetime

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


def get_quality_gate_status(sonar_url, project_key, token):
    """Fetch project quality gate status."""
    url = f"{sonar_url}/api/qualitygates/project_status?projectKey={project_key}"
    return fetch_json(url, token)


def get_project_metrics(sonar_url, project_key, token):
    """Fetch metrics from Sonar."""
    metrics = ",".join([
        "bugs", "vulnerabilities", "security_hotspots", "code_smells",
        "coverage", "duplicated_lines_density",
        "security_rating", "reliability_rating", "sqale_rating"
    ])
    url = f"{sonar_url}/api/measures/component?component={project_key}&metricKeys={metrics}"
    return fetch_json(url, token)


def extract_metric(data, metric_name):
    """Safely extract metric value from Sonar API response."""
    try:
        measures = data.get("component", {}).get("measures", [])
        for m in measures:
            if m.get("metric") == metric_name:
                return m.get("value", "0")
    except Exception:
        pass
    return "0"


def convert_rating(value):
    """Convert numeric Sonar rating (1–5) to letter grade."""
    mapping = {
        "A": 1, "1": 1, "1.0": 1,
        "B": 2, "2": 2, "2.0": 2,
        "C": 3, "3": 3, "3.0": 3,
        "D": 4, "4": 4, "4.0": 4,
        "E": 5, "5": 5, "5.0": 5
    }
    return mapping.get(str(value).upper(), 5)


def load_thresholds(threshold_path, project_key):
    """Load project-specific or default thresholds."""
    try:
        with open(threshold_path, "r") as f:
            all_thresholds = json.load(f)
    except FileNotFoundError:
        print(f"Threshold file not found: {threshold_path}")
        return None
    except json.JSONDecodeError:
        print(f"Invalid JSON in threshold file: {threshold_path}")
        return None

    thresholds = all_thresholds.get(project_key) or all_thresholds.get("default")
    if not thresholds:
        print(f"No thresholds found for '{project_key}' or 'default'.")
    return thresholds

def compare_metrics(metrics, thresholds, quality_status, sonar_url, project_key, branch=None): #branch=None
    """Compare metrics and quality gate status against thresholds."""
    def to_float(v):
        try:
            return float(v)
        except (ValueError, TypeError):
            return 0.0

    bugs = int(to_float(metrics["bugs"]))
    vulns = int(to_float(metrics["vulnerabilities"]))
    hotspots = int(to_float(metrics.get("security_hotspots", 0)))
    smells = int(to_float(metrics.get("code_smells", 0)))
    coverage = to_float(metrics["coverage"])
    duplicated = to_float(metrics["duplicated_lines_density"])
    rating = metrics["security_rating"]
    reliability = metrics.get("reliability_rating", "?")
    maintainability = metrics.get("sqale_rating", "?")

    # Default thresholds
    min_coverage = thresholds.get("coverage", 0)
    max_bugs = thresholds.get("bugs", 0)
    max_vulns = thresholds.get("vulnerabilities", 0)
    max_hotspots = thresholds.get("security_hotspots", 0)
    max_smells = thresholds.get("code_smells", 0)
    max_dup = thresholds.get("duplicated_lines_density", 100)
    min_rating = convert_rating(thresholds.get("security_rating", "E"))
    min_reliability = convert_rating(thresholds.get("reliability_rating", "E"))
    min_maintainability = convert_rating(thresholds.get("sqale_rating", "E"))

    print("\nSonar Metrics Summary:")
    print("----------------------")
    print(f"Quality Gate Status   : {quality_status}")
    print(f"Bugs                  : {bugs} (Max {max_bugs})")
    print(f"Vulnerabilities       : {vulns} (Max {max_vulns})")
    print(f"Security Hotspots     : {hotspots} (Max {max_hotspots})")
    print(f"Code Smells           : {smells} (Max {max_smells})")
    print(f"Coverage              : {coverage}% (Min {min_coverage}%)")
    print(f"Duplicated Lines      : {duplicated}% (Max {max_dup}%)")
    print(f"Security Rating       : {rating} (Min {min_rating})")
    print(f"Reliability Rating    : {reliability} (Min {min_reliability})")
    print(f"Maintainability Rating: {maintainability} (Min {min_maintainability})")


    fail_reasons = []

    if quality_status == "ERROR":
        fail_reasons.append("Quality gate failed in SonarQube")
    if coverage < min_coverage:
        fail_reasons.append("Coverage below threshold")
    if bugs > max_bugs:
        fail_reasons.append("Too many bugs")
    if vulns > max_vulns:
        fail_reasons.append("Too many vulnerabilities")
    if hotspots > max_hotspots:
        fail_reasons.append("Too many security hotspots")
    if smells > max_smells:
        fail_reasons.append("Too many code smells")
    if duplicated > max_dup:
        fail_reasons.append("High code duplication")
    if rating > min_rating:
        fail_reasons.append("Security rating below minimum")
    if reliability > min_reliability:
        fail_reasons.append("Reliability rating below minimum")
    if maintainability > min_maintainability:
        fail_reasons.append("Maintainability rating below minimum")

    sonar_project_url = f"{sonar_url}/dashboard?id={project_key}"

    if branch:
        sonar_project_url += f"&branch={branch}"

    print("\n=========================================")
    print("         Gate Decision")
    print("=========================================")
    print(f"SonarQube Report URL : {sonar_project_url}")
    
    if fail_reasons:
        print("\nQuality Gate FAILED")
        for reason in fail_reasons:
            print(f" - {reason}")
        return 2
    else:
        print("\nnQuality GATE PASSED — All checks within threshold")
        return 0

def main():
    parser = argparse.ArgumentParser(description="SonarQube Quality Gate & Threshold Checker")
    parser.add_argument("--sonar-host", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--project-key", required=True)
    parser.add_argument("--threshold-file", required=True)
    parser.add_argument("--branch", default=None)
    parser.add_argument("--wait", action="store_true", help="Wait for quality gate computation")
    args = parser.parse_args()

    sonar_url = args.sonar_host.rstrip("/")
    token = args.token
    project = args.project_key
    threshold_path = args.threshold_file
    branch = args.branch

    print(f"\nAnalyzing SonarQube Quality Gate for '{project}'")
    #print(f"Sonar URL: {sonar_url}")
    #print(f"Threshold file: {threshold_path}")

    thresholds = load_thresholds(threshold_path, project)
    if not thresholds:
        sys.exit(1)

    if args.wait:
        print(f"\nWaiting for quality gate computation...")
        for _ in range(60):  # ~5 minutes
            data = get_quality_gate_status(sonar_url, project, token)
            #print(data)
            status = data.get("projectStatus", {}).get("status", "NONE")
            if status != "NONE":
                break
            time.sleep(5)
    else:
        data = get_quality_gate_status(sonar_url, project, token)
        #print(data)
        status = data.get("projectStatus", {}).get("status", "UNKNOWN")

    if "error" in data:
        print(f"Error fetching quality gate: {data['error']}")
        sys.exit(2)

    metrics_data = get_project_metrics(sonar_url, project, token)
    if "error" in metrics_data:
        print(f"Error fetching metrics: {metrics_data['error']}")
        sys.exit(2)

    metrics = {
        "bugs": extract_metric(metrics_data, "bugs"),
        "vulnerabilities": extract_metric(metrics_data, "vulnerabilities"),
        "security_hotspots": extract_metric(metrics_data, "security_hotspots"),
        "code_smells": extract_metric(metrics_data, "code_smells"),
        "coverage": extract_metric(metrics_data, "coverage"),
        "duplicated_lines_density": extract_metric(metrics_data, "duplicated_lines_density"),
        "security_rating": convert_rating(extract_metric(metrics_data, "security_rating")),
        "reliability_rating": convert_rating(extract_metric(metrics_data, "reliability_rating")),
        "sqale_rating": convert_rating(extract_metric(metrics_data, "sqale_rating")),
    }

    exit_code = compare_metrics(metrics, thresholds, status, sonar_url, project, branch)
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
