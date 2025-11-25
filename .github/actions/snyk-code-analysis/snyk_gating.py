#!/usr/bin/env python3
import argparse
import json
import urllib.request
import sys
import os

# ---------------------------------------------------------
# Funciones auxiliares de logging
# ---------------------------------------------------------

def log(msg): 
    """Imprime mensajes informativos en consola."""
    print(f"[INFO] {msg}")

def err(msg):
    """Imprime errores usando el formato de GitHub Actions."""
    print(f"::error::{msg}")

# ---------------------------------------------------------
# Descarga de issues desde la API de Snyk
# ---------------------------------------------------------

def fetch_snyk_issues(api_url, org_id, project_name, token):
    """
    Llama a la API REST de Snyk para obtener las vulnerabilidades
    de un proyecto específico, filtrando por severidad.
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

# ---------------------------------------------------------
# Carga de resultados desde un archivo local (reporte Snyk)
# ---------------------------------------------------------

def load_from_report(report_path):
    """
    Carga y normaliza un archivo de resultados JSON de Snyk:
    Puede ser:
        - Un objeto con "vulnerabilities"
        - Una lista (formato alternativo)
    """
    if not os.path.exists(report_path):
        err(f"Report file not found: {report_path}")
        sys.exit(1)

    with open(report_path, "r") as f:
        data = json.load(f)

    issues_raw = None

    # Caso A: El archivo es un diccionario con vulnerabilidades
    if isinstance(data, dict):
        issues_raw = data.get("vulnerabilities", [])

    # Caso B: El archivo es una lista de issues
    elif isinstance(data, list):
        issues_raw = data

    else:
        err(f"Unexpected report format: must be dict or list, got {type(data)}")
        sys.exit(1)

    # Convertimos al formato estándar esperado por el gating
    formatted = []
    for issue in issues_raw:
        sev = issue.get("severity", issue.get("attributes", {}).get("severity", "unknown"))
        formatted.append({
            "attributes": {"severity": sev}
        })

    return formatted

# ---------------------------------------------------------
# Conteo de issues por severidad
# ---------------------------------------------------------

def count_by_severity(issues):
    """
    Cuenta el número de vulnerabilidades por severidad.
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for issue in issues:
        sev = issue.get("attributes", {}).get("severity")
        if sev in counts:
            counts[sev] += 1

    return counts

# ---------------------------------------------------------
# Carga de thresholds (umbrales por proyecto)
# ---------------------------------------------------------

def load_thresholds(threshold_file, project_key):
    """
    Carga los thresholds del archivo JSON combinando:
      - valores por defecto
      - overrides específicos del proyecto
    """
    with open(threshold_file, "r") as f:
        thresholds_data = json.load(f)

    default = thresholds_data.get("default", {})
    project_thresholds = thresholds_data.get(project_key, {})

    return {**default, **project_thresholds}

# ---------------------------------------------------------
# Evaluación de resultados vs thresholds
# ---------------------------------------------------------

def gate_results(counts, thresholds):
    """
    Compara el conteo de vulnerabilidades contra los thresholds
    definidos para determinar si el gating pasa o falla.
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

# ---------------------------------------------------------
# Main script
# ---------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Snyk Metrics Gating Script")

    parser.add_argument("--api-url", required=True, help="URL base de la API de Snyk")
    parser.add_argument("--org-id", required=True, help="ID de la organización en Snyk")
    parser.add_argument("--project-name", required=True, help="Nombre del proyecto Snyk")
    parser.add_argument("--token", required=True, help="Token de autenticación")
    parser.add_argument("--threshold-file", required=True, help="Archivo JSON con thresholds")
    parser.add_argument("--report-file", required=True, help="Archivo JSON del reporte Snyk local")

    args = parser.parse_args()

    # Convertir el nombre del proyecto a una key válida
    project_key = args.project_name.replace("/", "_")
    
    # Cargar thresholds según el proyecto
    thresholds = load_thresholds(args.threshold_file, project_key)

    # Priorizar archivo local, si existe
    if args.report_file and os.path.exists(args.report_file):
        log(f"Loading Snyk issues from local report: {args.report_file}")
        issues = load_from_report(args.report_file)
    else:
        log(f"Fetching Snyk issues for '{args.project_name}' via API...")
        issues = fetch_snyk_issues(args.api_url, args.org_id, args.project_name, args.token)

    # Obtener métricas
    counts = count_by_severity(issues)

    log("Fetched Snyk issue summary:")
    for sev, count in counts.items():
        log(f"  {sev.title()}: {count}")

    # Evaluar contra thresholds
    failed = gate_results(counts, thresholds)

    # URL para el usuario
    snyk_project_url = f"https://app.snyk.io/org/{args.org_id}/projects/{args.project_name}"

    print("\n=========================================")
    print("             Gate Decision")
    print("=========================================")
    print(f"Snyk Report URL : {snyk_project_url}")

    # Lógica opcional de fallo (actualmente comentada)
    # if failed:
    #     print("Gating Result   : FAILED (Thresholds exceeded)")
    #     print("=========================================\n")
    #     sys.exit(1)
    # else:
    #     log("Snyk gating passed successfully.")
    #     sys.exit(0)

if __name__ == "__main__":
    main()
