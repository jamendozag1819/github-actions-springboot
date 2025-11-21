# Documentación del Flujo CI/CD

Este documento describe el flujo completo del pipeline CI/CD
implementado con GitHub Actions, incluyendo análisis de seguridad,
calidad de código, pruebas unitarias y evaluación de puertas de
seguridad (gates).

## 📌 1. Visión General del Pipeline

El pipeline se ejecuta en los siguientes escenarios:

-   Push a ramas `main` o `*release*`
-   Pull Request hacia `main` o `*release*`
-   Ejecución manual vía *workflow_dispatch*

El flujo completo incluye:

1.  **Security Scanning (Snyk)**
2.  **Code Quality Analysis (SonarCloud)**
3.  **Unit Testing (opcional)**
4.  **Evaluación de puertas de seguridad (Security & Quality Gates)**

------------------------------------------------------------------------

## 🔐 2. Security Scanning (Snyk)

Archivo: `.github/workflows/security-scanning.yml`

### Objetivo

Detectar vulnerabilidades: - Dependencias (Snyk OSS) - Código fuente
(Snyk Code) - Según el stack detectado automáticamente

### Flujo Interno

1.  Detecta stack usando `snyk-tech.py`
2.  Mapea el comando correcto vía `snyk-command-map.py`
3.  Ejecuta:
    -   `snyk code test`
    -   `snyk test`
4.  Genera `snyk-results.json` y `snyk-code-results.json`
5.  Publica artefactos para el job **evaluate-gates**

------------------------------------------------------------------------

## 🧪 3. Code Quality (SonarCloud)

Archivo: `.github/workflows/quality-analysis.yml`

### Objetivo

Evaluar calidad del código:

-   Bugs
-   Vulnerabilidades
-   Code smells
-   Duplicación
-   Hotspots
-   Cobertura (si se proveen resultados)

### Flujo Interno

1.  Detecta tecnologías con `sonar-tech.py`
2.  Genera `sonar-project.properties` automáticamente
3.  Ejecuta `sonar-scanner`
4.  Llama al script `sonar_gating.py` para validar gates
5.  Publica `quality-gate-result.json` como artefacto

------------------------------------------------------------------------

## 🧪 4. Unit Testing (Opcional)

Archivo: `.github/workflows/unit-testing.yml`

### Objetivo

-   Ejecutar pruebas unitarias según el stack:
    -   Maven / Gradle
    -   Node / Angular
    -   Python
-   Generar:
    -   Reportes JUnit
    -   Reportes JaCoCo (o equivalentes)
    -   Artefacto `test-results`

### Flujo Interno

1.  Detecta el stack recibido por el workflow caller
2.  Ejecuta el runner adecuado
3.  Calcula:
    -   Total tests
    -   Fallidos
    -   Skipped
    -   Cobertura
4.  Genera estado:
    -   PASSED
    -   WARNING
    -   FAILED
5.  Publica artefactos para gates

------------------------------------------------------------------------

## 🛡️ 5. Enterprise Gate Evaluation

Archivo: `.github/workflows/evaluate-gates.yml`

### Objetivo

Validar si el proyecto cumple con los umbrales:

-   Seguridad (Snyk)
-   Calidad (Sonar)
-   Cobertura (Unit Testing)

### Datos que procesa

  Fuente      Archivo
  ----------- -----------------------------------
  Sonar       `quality-gate-result.json`
  Snyk OSS    `snyk-results.json`
  Snyk Code   `snyk-code-results.json`
  Tests       `test-results/`
  Overrides   `overrides/final-thresholds.json`

### Resultados

Produce:

-   `gate-decision.json`
-   Estado final: **PASS / WARN / BLOCK**

También genera un resumen en GitHub Actions.

------------------------------------------------------------------------

## 🔗 6. Pipeline Principal: deploy.yml

Archivo: `.github/workflows/deploy.yml`

### Orden de ejecución

1️⃣ security-scan\
2️⃣ code-quality\
3️⃣ evaluate-gates

Si alguna puerta se bloquea → el pipeline falla.

### Ejecución Manual

El usuario puede pasar:

    override_gates: true

Para permitir despliegue aunque las puertas fallen.

------------------------------------------------------------------------

## 🧩 7. Arquitectura General del CI/CD

            ┌────────────────────────────────────┐
            │            DEPLOY.YML              │
            └────────────────────────────────────┘
                              │
         ┌────────────────────┴─────────────────────┐
         │                                          │
    ┌──────────────┐                         ┌─────────────────┐
    │ SECURITY-SCAN│                         │ CODE-QUALITY    │
    │   (Snyk)     │                         │  (Sonar)        │
    └──────────────┘                         └─────────────────┘
              │                                       │
              └────────────────────┬──────────────────┘
                                   │
                        ┌───────────────────┐
                        │  EVALUATE-GATES   │
                        └───────────────────┘
                                   │
                            PASS / BLOCK

------------------------------------------------------------------------

## 📦 8. Artefactos Generados

  Proceso           Artefacto
  ----------------- ---------------------
  Snyk              `security-results/`
  Sonar             `quality-results/`
  Unit Testing      `test-results/`
  Gate evaluation   `gate-decision/`

------------------------------------------------------------------------

## ✔️ 9. Beneficios del Pipeline

-   Multistack automático (Java, Node, Angular, Python, etc.)
-   Calidad y seguridad unificadas
-   Puertas de aprobación tipo enterprise
-   Compatible con overrides para desarrolladores
-   Totalmente modular y reutilizable
-   Artefactos portables entre jobs

------------------------------------------------------------------------

## 📄 10. Mantenimiento futuro

Se recomienda:

-   Mantener actualizados umbrales en `overrides/final-thresholds.json`
-   Mejorar reglas de Sonar
-   Añadir integración opcional con:
    -   Dependabot
    -   GitLeaks
    -   Trivy (Docker)
-   Añadir reportes PDF con resultados

------------------------------------------------------------------------

### ¿Deseas que genere un diagrama visual PNG del flujo?

¿O deseas una versión PDF de esta documentación?
