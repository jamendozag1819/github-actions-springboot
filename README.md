<<<<<<< HEAD
# Correlación entre diseño de alto nivel y diseño detallado  
**Proyecto:** Pipeline CI/CD con Snyk, SonarCloud, Jira y Deploy en OpenShift

| Sección | Información |
|--------|-------------|
| **Países afectados** | No aplica (pipeline interno de desarrollo; sin impacto regional). |
| **Aplicación afectada** | CI/CD Pipeline – GitHub Actions para aplicación **myapp**. |
| **Aplicaciones conectadas** | - **Snyk API** (SCA, SAST, Container)<br>- **SonarCloud API**<br>- **Jira Cloud API** (actualización de tickets)<br>- **OpenShift Cluster API** (deploy con OC/Helm/Ansible)<br>- **Artifactory/Helm repo** (solo si aplicaba para pulls de chart o imágenes, según tu configuración actual). |
| **Aplicaciones de soporte** | - GitHub Actions runners<br>- Docker Engine<br>- Python + Ansible<br>- Helm CLI<br>- OC CLI |
| **Diseño técnico detallado necesario (S/N)** | **Sí** |
| **Justificación si no fuera necesario** | *No aplica*, porque el pipeline tiene integración con múltiples sistemas externos y requiere un diseño técnico claro para auditoría, reproducibilidad y control de cambios. |
| **Si se creará más de un diseño técnico detallado** | Todo puede quedar en **un solo documento**, pero dividido en módulos:<br>- Módulo Snyk<br>- Módulo Sonar<br>- Módulo Jira<br- Módulo Deploy OpenShift<br>- Módulo Artefactos y Docker |
| **Revisión de código requerida (Y/N)** | **Sí** — Todo cambio al pipeline se maneja mediante **Pull Request + Code Review obligatorio**. |
| **Plan de Recuperación (ARP) creado/actualizado (S/N)** | **Sí (parcial)** — El rollback existe en Ansible (`cd_rollback.yml`) pero está comentado; requiere formalizarse como ARP. |
| **Pruebas de Integración del Desarrollo (DIT) realizadas (Y/N)** | **Sí** — Se valida:<br>- Build Docker<br>- Snyk scan<br>- Sonar scan<br>- Jira update<br>- Deploy en OpenShift (DEV). |
| **Casos de Uso / Funcionalidad** |  |
| **Caso de uso 1** | **Escaneo de seguridad automático**:<br>- Snyk SCA, SAST y Container.<br>- Generación de reporte JSON.<br>- Aplicación de *gating thresholds*. |
| **Caso de uso 2** | **Calidad del código (SonarCloud)**:<br>- Análisis estático.<br>- Uso de tokens protegidos.<br>- Reporte en dashboard. |
| **Caso de uso 3** | **Integración con Jira**:<br>- Actualización de estado.<br>- Asociación del commit/PR con ticket. |
| **Caso de uso 4** | **Build y Deploy automático en OpenShift**:<br>- Construcción de imagen Docker.<br>- Carga como artefacto.<br>- Deploy con Helm + Ansible.<br>- Validación de namespaces, charts y versión. |
| **Caso de uso N** | Escalamiento en pipelines futuros: pruebas automatizadas, integración con Artifactory, ambientes QA/UAT. |
=======
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
>>>>>>> SCRUM-6-release-snik-jira
