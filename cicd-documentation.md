
# CI/CD Pipeline Documentation

## Overview

This document describes the full CI/CD architecture implemented using GitHub Actions.  
The pipeline integrates:

- **Snyk Security Scanning** (SAST + Dependency Scanning)
- **SonarCloud Code Quality Analysis**
- **Enterprise Gate Evaluation**
- **Multi‑stack auto‑detection**
- **Reusable workflows & composite actions**

---

## 1. Main Pipeline: `deploy.yml`

### Triggers
The pipeline runs on:
- Push to `main` or any `*release*` branch
- Pull Requests into the same branches
- Manual dispatch (with override options)

### Stages

| Stage | Workflow | Purpose |
|-------|----------|---------|
| `security-scan` | `security-scanning.yml` | Snyk SAST + Dependency scanning |
| `code-quality` | `quality-analysis.yml` | SonarCloud scan + quality gate |
| `evaluate-gates` | `evaluate-gates.yml` | Enterprise security + quality gating |

---

## 2. Security Scanning: `security-scanning.yml`

### Features
- Detects backend stack using `snyk-tech.py`
- Maps Snyk command using `snyk-command-map.py`
- Runs:
  - **Snyk Code (SAST)**
  - **Snyk Test (Dependency Vulnerabilities)**
- Exports vulnerability counts
- Uploads artifacts for gating

### Inputs
- `java-version`
- `SNYK_TOKEN`
- `SNYK_ORG_ID`

### Outputs
- Critical, High, Medium, Low vulnerability counts  
- Auto‑detected `stack`

---

## 3. Code Quality Analysis: `quality-analysis.yml`

### Features
- Auto-detects project tech stack using `sonar-tech.py`
- Generates `sonar-project.properties` dynamically using config profile fragments
- Runs SonarCloud scan
- Validates Sonar Quality Gate using `sonar_gating.py`

### Outputs
- Quality gate status
- Metrics summary
- Scan results exported as artifacts

---

## 4. Evaluate Enterprise Gates: `evaluate-gates.yml`

This stage consolidates:

- Snyk dependency results  
- Snyk Code SAST results  
- Sonar Cloud Quality results  
- Optional developer overrides (`final-thresholds.json`)  

### Metrics evaluated
| Category | Metrics |
|----------|---------|
| Snyk | Critical, High, Medium vulnerabilities |
| SonarQube | Coverage, Bugs, Vulnerabilities, Code smells |
| Overrides | Security gating exceptions |

### Outputs
- Final gate decision: **PASS / WARN / BLOCK**
- Reason summary
- Consolidated GitHub Summary table

---

## 5. Sonar Composite Action: `sonar-code-analysis/action.yml`

This action:

1. Installs Java, Node, Python
2. Installs Sonar Scanner CLI
3. Detects tech stack → generates properties
4. Runs Sonar Scan
5. Executes threshold gating via Python script

---

## 6. Tech Stack Detection Scripts

### `sonar-tech.py`
Detects stack for **Sonar** and selects correct property bundles:
- Maven / Gradle
- Node / Angular
- Python
- Android / iOS
- Common defaults

### `snyk-tech.py`
Detects stack for **Snyk** CLI execution

### `snyk-command-map.py`
Maps detected stack → correct Snyk CLI command.

---

## 7. Artifacts Generated

| Stage | Artifact | Path |
|--------|----------|-------|
| Snyk | Dependency scan | `snyk-scanning/results/snyk-results.json` |
| Snyk Code | SAST | `snyk-scanning/results/snyk-code-results.json` |
| Sonar | Quality results | `sonarqube-cloud-scanning/results/` |
| Unit Tests | Coverage + JUnit | `test-results/` |
| Gate Decision | Final decision | `gate-decision.json` |

---

## 8. Data Flow Summary

```
security-scan ──► produces Snyk results
      │
      ▼
code-quality ───► produces Sonar results
      │
      ▼
evaluate-gates ─► merges all results & decisions
```

---

## 9. Extensibility

This CI/CD pipeline supports:

- Multi‑stack environments
- Plug‑and‑play workflows
- Custom developer overrides
- Emergency deployment override
- Automatic detection for: Java, Node, Angular, Python, Docker, Android, iOS

---

## 10. Conclusion

Your pipeline is now structured as an **enterprise‑grade CI/CD framework**, with:

- Security-first scanning architecture
- Automated quality governance
- Clear pass/fail rules
- Modular, reusable GitHub Actions components
- Full auditability through artifacts & summaries

---

