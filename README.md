# Prueba Técnica — Cybersecurity Specialist (FinCloud Invest)

**Candidato:** Jawy Romero ([@Jawy77](https://github.com/Jawy77))
**Fecha:** Julio 2026

Este repositorio contiene los entregables de la prueba técnica para el rol de **Cybersecurity Specialist**,
sobre el caso de negocio de la fintech **FinCloud Invest**.

## Contenido

| Punto | Entregable | Archivo |
|-------|-----------|---------|
| 1, 2 y 3 | Documento principal: análisis de riesgos cloud, AppSec/Threat Modeling y priorización de vulnerabilidades | [`Respuesta_Tecnica_Cybersecurity_Specialist.md`](Respuesta_Tecnica_Cybersecurity_Specialist.md) |
| 2 | Threat Model STRIDE de "Transferencia Rápida" | [`threat_model_stride_quick_transfer.md`](threat_model_stride_quick_transfer.md) |
| 1.4 | Diagrama de Arquitectura Zero Trust (iconos oficiales AWS) | [`fincloud_zero_trust_aws_official.png`](fincloud_zero_trust_aws_official.png) |
| 1.4 | Diagrama de Arquitectura Zero Trust (alternativo) | [`fincloud_zero_trust_architecture.png`](fincloud_zero_trust_architecture.png) |
| 1.4 | Código fuente de los diagramas (`diagrams` / Python) | [`diagrama_zero_trust_aws.py`](diagrama_zero_trust_aws.py), [`diagrama_zero_trust.py`](diagrama_zero_trust.py) |
| 1.4 | Fuentes editables draw.io | [`fincloud_zero_trust.drawio`](fincloud_zero_trust.drawio), [`fincloud_zero_trust_aws_icons.drawio`](fincloud_zero_trust_aws_icons.drawio) |

## Estructura de la Respuesta

- **Punto 1 — Riesgos y Controles Cloud:** identificación de riesgos (con probabilidad/impacto y mapeo a
  ATT&CK/CIS), controles recomendados (mapeados a NIST CSF 2.0), matriz de priorización con SLAs y
  arquitectura **Zero Trust** basada en NIST SP 800-207.
- **Punto 2 — AppSec / Threat Modeling:** amenazas, vulnerabilidades por capa (Web/Móvil/API con OWASP Top 10),
  controles preventivos y detectivos, y actividades de **Secure SDLC**.
- **Punto 3 — Gestión de Vulnerabilidades:** priorización defendible (CVSS + EPSS + CISA KEV + sensibilidad del
  dato), primera remediación, información adicional requerida y justificación ante desarrollo y liderazgo.

## Marcos de Referencia Utilizados

AWS Well-Architected (Security Pillar) · CIS AWS Foundations Benchmark · NIST CSF 2.0 ·
NIST SP 800-207 (Zero Trust) · OWASP Top 10 (Web/API/Móvil), ASVS/MASVS · MITRE ATT&CK / D3FEND ·
FIRST CVSS v3.1 + EPSS + CISA KEV.

## Reproducir los Diagramas

```bash
pip install diagrams   # requiere Graphviz instalado
python3 diagrama_zero_trust_aws.py   # genera fincloud_zero_trust_aws_official.png
python3 diagrama_zero_trust.py       # genera fincloud_zero_trust_architecture.png
```
