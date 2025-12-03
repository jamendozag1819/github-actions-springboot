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
