#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Este script genera una tabla resumen legible de los resultados contenidos
en un archivo `gate-result.json`, mostrando la información de cada GATR (regla)
junto con su categoría y estado final.

El objetivo principal es transformar el JSON generado por el evaluador
`gate_evaluator.py` en una tabla Markdown para usar en reportes, README,
o GitHub Step Summary.

USO:
    python gate_summary.py gating/gate-result.json

ENTRADA:
    - Un JSON con estructura:
        {
          "final_decision": "PASS/WARN/FAIL",
          "gates": [
            { "id": "gatr-01", "status": "PASS", ... },
            { "id": "gatr-08", "status": "FAIL", ... }
          ]
        }

SALIDA:
    Imprime líneas en formato Markdown:

    | gatr-01 | High Vulnerability | Security | NON_ENFORCING | Snyk | Yes | PASS |
"""

import json
import sys

# ---------------------------------------------------------------
# Diccionario de metadatos por cada regla GATR
# ---------------------------------------------------------------
# Formato:
#   id: (Nombre legible, Categoría, Tipo, Fuente, Visible en reporte)
#
# Tipo:
#   - ENFORCING → Si falla, bloquea despliegue
#   - NON_ENFORCING → Solo muestra advertencias
#
# Visible:
#   - Yes → Mostrar al usuario en reportes
#   - No  → Solo uso interno
#
GATE_INFO = {
    "gatr-01": ("High Vulnerability", "Security", "NON_ENFORCING", "Snyk", "Yes"),
    "gatr-02": ("Medium Vulnerability", "Security", "NON_ENFORCING", "Snyk", "Yes"),
    "gatr-03": ("Critical Vulnerability", "Security", "NON_ENFORCING", "Snyk", "Yes"),
    "gatr-07": ("Developer Thresholds", "Quality", "NON_ENFORCING", "SonarQube", "Yes"),
    "gatr-08": ("Code Quality", "Quality", "ENFORCING", "SonarQube", "Yes"),
    "gatr-09": ("Approved Sonar Params", "Quality", "ENFORCING", "GitHub Actions", "No"),
    "gatr-10": ("Express Lane Quality", "Quality", "NON_ENFORCING", "SonarQube", "Yes"),
    "gatr-14": ("Release Branch", "Governance", "ENFORCING", "GitHub Actions", "No"),
}


# ---------------------------------------------------------------
# Main
# ---------------------------------------------------------------
def main():
    """
    Punto de entrada del script:
      - Lee archivo JSON de resultados del Gate Evaluator
      - Itera por cada regla evaluada
      - Busca sus metadatos en GATE_INFO
      - Imprime una fila en formato Markdown
    """
    if len(sys.argv) < 2:
        print("ERROR: Missing gate-result.json path", file=sys.stderr)
        sys.exit(1)

    path = sys.argv[1]

    # Cargar archivo JSON con los resultados del pipeline
    with open(path) as f:
        data = json.load(f)

    # Recorrer cada gate evaluado
    for g in data["gates"]:
        gid = g["id"]

        # Si la regla existe en GATE_INFO, tomar su metadata,
        # si no, usar valores 'Unknown'
        label = GATE_INFO.get(
            gid,
            ("Unknown", "Unknown", "Unknown", "Unknown", "Unknown")
        )

        # Imprime fila Markdown
        print(
            f"| {gid} | {label[0]} | {label[1]} | {label[2]} | "
            f"{label[3]} | {label[4]} | {g['status']} |"
        )


if __name__ == "__main__":
    main()
