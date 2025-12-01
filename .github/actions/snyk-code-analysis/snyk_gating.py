#!/usr/bin/env python3
"""
Snyk Gating Script
-------------------------------------------
Este script evalúa los resultados de vulnerabilidades de Snyk
(ya sea desde un archivo local generado con `--json-file-output`
o directamente usando la API REST de Snyk), y valida si se cumplen
los umbrales definidos para permitir o bloquear un pipeline.

Flujo general:
1. Cargar thresholds desde un JSON.
2. Obtener vulnerabilidades (archivo local o API).
3. Contarlas por severidad.
4. Compararlas contra los thresholds.
5. Salir con código 0 (OK) o 1 (Fallo del gate).
"""

import argparse
import json
import urllib.request
import sys
import os

# ------------------------------------------------------------
# Utilidades de logging
# ------------------------------------------------------------
def log(msg):
    """Imprime mensajes informativos estándar."""
    print(f"[INFO] {msg}")

def err(msg):
    """Imprime mensajes de error en formato compatible con GitHub Actions."""
    print(f"::error::{msg}")

# ------------------------------------------------------------
# Llamado a la API REST de Snyk para obtener issues
# ------------------------------------------------------------
def fetch_snyk_issues(api_url, org_id, project_name, token):
    """
    Obtiene las vulnerabilidades desde la API oficial de Snyk.
    Filtra por:
        - organización
        - nombre del proyecto
        - severidades: low, medium, high, critical
    """

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

# ------------------------------------------------------------
# Lectura de issues desde un reporte JSON local
# ------------------------------------------------------------
def load_from_report(report_path):
    """
    Carga vulnerabilidades desde un archivo local generado por Snyk.
    Normaliza el formato a algo similar a la API de Snyk:
      → attributes.severity
    """
    if not os.path.exists(report_path):
        err(f"Report file not found: {report_path}")
        sys.exit(1)

    with open(report_path, "r") as f:
        data = json.load(f)

    issues = data.get("vulnerabilities", [])
    formatted = []

    for issue in issues:
        formatted.append({
            "attributes": {
                "severity": issue.get("severity", "unknown")
            }
        })

    return formatted

# ------------------------------------------------------------
# Contar vulnerabilidades por severidad
# ------------------------------------------------------------
def count_by_severity(issues):
    """
    Recibe una lista de issues y cuenta cuantas hay
    por severidad: critical, high, medium, low.
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for issue in issues:
        sev = issue.get("attributes", {}).get("severity")
        if sev in counts:
            counts[sev] += 1

    return counts

# ------------------------------------------------------------
# Carga y fusión de thresholds por proyecto
# ------------------------------------------------------------
def load_thresholds(threshold_file, project_key):
    """
    Carga el archivo JSON de thresholds.
    Permite:
        - un bloque "default" con thresholds globales
        - thresholds específicos por project_key
    Se fusionan: específicos > default
    """

    with open(threshold_file, "r") as f:
        thresholds_data = json.load(f)

    default = thresholds_data.get("default", {})
    project_thresholds = thresholds_data.get(project_key, {})

    # Mezclado: lo específico sobrescribe lo global
    merged = {**default, **project_thresholds}
    return merged

# ------------------------------------------------------------
# Validación del gate: comparar counts vs thresholds
# ------------------------------------------------------------
def gate_results(counts, thresholds):
    """
    Compara las cantidades encontradas con los
    umbrales permitidos por severidad.
    Si alguna severidad excede el threshold → gating falla.
    """
    failed = False

    for sev, count in counts.items():
        allowed = thresholds.get(sev, 0)

        if count > allowed:
            err(f"{sev.title()} issues ({count}) exceed threshold ({allowed})")
            failed = True
        else:
            log(f"{sev.title()} within threshold: {count}/{allowed}")

    return failed

# ------------------------------------------------------------
# Función principal
# ------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Snyk Metrics Gating Script")

    parser.add_argument("--api-url", required=True)
    parser.add_argument("--org-id", required=True)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--threshold-file", required=True)
    parser.add_argument("--report-file", required=True)

    args = parser.parse_args()

    # Project key estándar para thresholds (sin slashes)
    project_key = args.project_name.replace("/", "_")

    # Cargar thresholds de seguridad
    thresholds = load_thresholds(args.threshold_file, project_key)

    # Determinar origen del reporte: archivo local o API
    if args.report_file and os.path.exists(args.report_file):
        log(f"Loading Snyk issues from local report: {args.report_file}")
        issues = load_from_report(args.report_file)
    else:
        log(f"Fetching Snyk issues for '{args.project_name}' via API...")
        issues = fetch_snyk_issues(
            args.api_url,
            args.org_id,
            args.project_name,
            args.token
        )

    # Contar vulnerabilidades
    counts = count_by_severity(issues)

    log("Fetched Snyk issue summary:")
    for sev, count in counts.items():
        log(f"  {sev.title()}: {count}")

    # Validación de umbrales
    failed = gate_results(counts, thresholds)

    snyk_project_url = f"https://app.snyk.io/org/{args.org_id}/projects/{args.project_name}"

    print("\n=========================================")
    print("             Gate Decision")
    print("=========================================")
    print(f"Snyk Report URL : {snyk_project_url}")

    # Exit code define si el pipeline continúa o falla
    if failed:
        print("Gating Result   : FAILED (Thresholds exceeded)")
        print("=========================================\n")
        sys.exit(1)
    else:
        log("Snyk gating passed successfully.")
        sys.exit(0)


if __name__ == "__main__":
    main()
