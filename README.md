# README --- Implementación de Governance Gates para CI/CD con SonarCloud

Este documento describe la implementación de compuertas (Gates) de
calidad y gobernanza dentro del pipeline de CI/CD.

## Gates Implementadas

  -----------------------------------------------------------------------------
  Gate ID       Nombre                                  Tipo         Pipeline
  ------------- --------------------------------------- ------------ ----------
  **gatr-08**   Code Quality                            Calidad      CI

  **gatr-09**   Approved Sonar Parameters               Gobernanza   CI

  **gatr-14**   Release Branch Validation               Gobernanza   CD
  -----------------------------------------------------------------------------

## Arquitectura General

    CI Pipeline (PR / Push)
        ├─ Build
        ├─ Sonar Scanner
        ├─ Sonar Gating Script
        │     ├─ gatr-08 (Code Quality)
        │     └─ gatr-09 (Sonar Params)
        └─ Snyk Scan (SCA/SAST)

    CD Pipeline (Deploy)
        └─ gatr-14 (Release Branch Validation)

## Gate gatr-08 --- Code Quality

Valida SonarCloud Quality Gate, ratings mínimos y métricas definidas en
`sonar_thresholds.json`.

## Gate gatr-09 --- Approved Sonar Parameters

Garantiza que no se utilicen parámetros prohibidos como:

-   `sonar.exclusions`
-   `sonar.skip`
-   `sonar.test.exclusions`

Permite únicamente:

-   `sonar.coverage.exclusions`
-   `sonar.cpd.exclusions`

## Gate gatr-14 --- Release Branch Validation

Bloquea despliegues a UAT/PROD desde ramas no autorizadas.

## Ejemplo de uso en CI

``` bash
python3 scripts/sonar_gating.py \
  --sonar-host "https://sonarcloud.io" \
  --token "${{ secrets.SONAR_TOKEN }}" \
  --project-key "${{ secrets.SONAR_PROJECT_KEY }}" \
  --threshold-file "gating-configs/sonar_thresholds.json" \
  --branch "${GITHUB_REF#refs/heads/}" \
  --environment "DEV" \
  --wait
```

## Ejemplo de archivo sonar_thresholds.json

``` json
{
  "default": {
    "coverage": 80,
    "bugs": 5,
    "vulnerabilities": 2,
    "security_hotspots": 5,
    "code_smells": 50,
    "duplicated_lines_density": 5,
    "security_rating": "B",
    "reliability_rating": "B",
    "sqale_rating": "B"
  }
}
```
