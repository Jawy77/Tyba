# Prueba Técnica — Cybersecurity Specialist
## FinCloud Invest: Seguridad Cloud, AppSec y Gestión de Vulnerabilidades

**Candidato:** Jawy Romero (@Jawy77)
**Fecha:** Julio 2026
**Alcance:** Análisis de riesgos de la arquitectura cloud, Threat Modeling de "Transferencia rápida" y priorización de vulnerabilidades.

---

## Resumen Ejecutivo

FinCloud Invest opera una plataforma fintech regulada (web + móvil + API pública) sobre AWS con varias
debilidades estructurales: políticas IAM amplias, segregación de ambientes incompleta, secretos gestionados
parcialmente, logs sin correlación, CVEs de dependencias sin priorizar, un endpoint de API que expone datos
de más y la ausencia de un proceso formal de threat modeling. Individualmente son manejables; combinadas
generan un **radio de impacto (blast radius) amplio**, donde una sola credencial filtrada puede escalar hasta
datos de producción o fondos de clientes.

Este documento entrega tres bloques alineados a la prueba:

1. **Análisis de riesgos y controles cloud** mapeado a marcos de la industria (AWS Well-Architected Security
   Pillar, CIS AWS Foundations Benchmark, NIST CSF 2.0, NIST SP 800-207 Zero Trust), con una hoja de ruta priorizada.
2. **Un threat model de "Transferencia rápida"** (STRIDE + OWASP Top 10 Web/Móvil/API) con controles
   preventivos y detectivos e integración con el Secure SDLC.
3. **Una priorización de vulnerabilidades defendible** usando el modelo Riesgo = Exposición × Explotabilidad ×
   Impacto (CVSS + EPSS + CISA KEV + sensibilidad del dato), con SLAs de remediación y justificación para los stakeholders.

**Principio rector:** proteger primero la *licencia para operar* (autenticación/autorización en funciones
sensibles y CVEs críticas expuestas a internet), luego reducir el blast radius (IAM de mínimo privilegio,
segmentación, secretos) y finalmente construir detección y prevención duraderas (SIEM, gates DevSecOps, threat
modeling) — todo sin frenar la entrega, desplazando la seguridad "a la izquierda" (shift-left) y automatizando
los controles en el CI/CD.

### Alineación con Marcos de Referencia (vista rápida)

| Marco | Cómo se usa en este documento |
|-------|-------------------------------|
| **AWS Well-Architected — Security Pillar** | Estructura los dominios de control (IAM, detección, protección de infraestructura, protección de datos, respuesta a incidentes). |
| **CIS AWS Foundations Benchmark** | Líneas base concretas de hardening (MFA en root, CloudTrail multi-región, bloqueo de acceso público a S3). |
| **NIST CSF 2.0** | Mapeo de controles a Gobierno / Identificar / Proteger / Detectar / Responder / Recuperar. |
| **NIST SP 800-207 (Zero Trust)** | Base de la arquitectura Zero Trust del Punto 1.4. |
| **OWASP Top 10 (Web / API / Móvil) y ASVS/MASVS** | Taxonomía de vulnerabilidades del Threat Model del Punto 2. |
| **MITRE ATT&CK / D3FEND** | Casos de detección y mapeo de técnicas de adversario para el SIEM. |
| **FIRST CVSS v3.1 + EPSS + CISA KEV** | Priorización cuantitativa de vulnerabilidades del Punto 3. |

---

## Punto 1. Análisis de Riesgos y Controles sobre la Arquitectura Cloud

### 1. Principales Riesgos de Seguridad Cloud Identificados

| ID | Riesgo | Descripción | Probabilidad | Impacto | Ref (ATT&CK / CIS / OWASP) |
|----|--------|-------------|--------------|---------|----------------------------|
| R1 | **IAM demasiado permisiva** | Roles con políticas amplias (p. ej. `*:*`) habilitan movimiento lateral y escalamiento de privilegios si se compromete una credencial. | Alta | Crítico | TA0004 / CIS 1.x |
| R2 | **Falta de segregación de ambientes** | Redes no aisladas permiten a un atacante pivotar desde dev/staging hacia cargas de producción. | Media | Alto | TA0008 / CIS 5.x |
| R3 | **Secretos en variables de entorno** | Los secretos en env vars pueden filtrarse vía logs, backups, introspección de contenedores o listado de procesos. | Alta | Alto | T1552.001 |
| R4 | **Logs de seguridad sin correlación** | Logs dispersos (CloudTrail, ALB, VPC Flow, aplicación) impiden detección oportuna y análisis forense. | Alta | Alto | TA0005 / CIS 3.x |
| R5 | **Vulnerabilidades de dependencias sin priorizar** | CVEs conocidas en librerías de terceros son escaneadas activamente por atacantes; sin priorización, las ventanas de explotación quedan abiertas. | Alta | Alto | T1190 |
| R6 | **Sobreexposición de la API** | Endpoints que devuelven más datos de los necesarios facilitan fuga masiva de datos e incumplimiento regulatorio. | Alta | Alto | OWASP API3 |
| R7 | **Ausencia de threat modeling formal** | Los proyectos nuevos carecen de análisis de seguridad estructurado en diseño, acumulando deuda de seguridad y fallas arquitectónicas. | Media | Medio | NIST SSDF |
| R8 | **CI/CD como vector de ataque** | Despliegues automáticos sin gates de seguridad pueden llevar código malicioso o vulnerable directo a producción. | Media | Alto | T1195.002 |
| R9 | **Protección de datos débil / exposición de PII** | Números de documento completos y datos financieros devueltos/almacenados sin enmascaramiento ni tokenización aumentan el fraude y la exposición regulatoria. | Alta | Alto | OWASP API3 |

### 2. Controles Recomendados

| Dominio | Control | Enfoque de Implementación |
|---------|---------|---------------------------|
| **IAM** | Mínimo privilegio + RBAC + acceso JIT | Auditar políticas con IAM Access Analyzer; imponer rol-por-servicio; eliminar llaves de larga duración; exigir MFA para acciones privilegiadas. |
| **Red** | Segregación de ambientes + microsegmentación | VPCs separadas para dev/staging/prod; Security Groups/NACLs restrictivos; subredes privadas para bases de datos y APIs internas. |
| **Secretos** | Gestión centralizada de secretos | Migrar secretos de env vars a AWS Secrets Manager o SSM Parameter Store (SecureString) con rotación automática. |
| **Logging y Monitoreo** | SIEM centralizado + correlación | Enviar CloudTrail, VPC Flow Logs, logs de ALB/WAF y de contenedores a un SIEM (p. ej. Splunk, Sentinel o ELK). Construir reglas de detección y dashboards. |
| **Gestión de Vulnerabilidades** | Integración SCA / SAST / DAST | Incrustar escaneo de dependencias (SCA) y análisis estático (SAST) en CI/CD con políticas de bloqueo (break-glass); DAST periódico. |
| **Seguridad de API** | Minimización de datos + validación estricta de esquema | Filtrado de respuestas (solo campos requeridos); validar entradas contra esquemas OpenAPI; usar modelos de seguridad positiva. |
| **Diseño Seguro** | Threat modeling obligatorio | Exigir análisis STRIDE o PASTA antes de iniciar desarrollo en cualquier proyecto o funcionalidad relevante. |
| **Seguridad de Contenedores** | Escaneo de imágenes + hardening | Escanear imágenes en Amazon ECR; ejecución sin root, filesystems de solo lectura y Pod Security Standards. |
| **Protección de Datos** | Enmascaramiento + tokenización + cifrado | Enmascarar PII (`****1234`); tokenizar datos financieros; cifrado en reposo (KMS) y en tránsito (TLS 1.3). |

#### Mapeo de Controles a Marco (NIST CSF 2.0)

| Función NIST CSF | Controles que aporta |
|------------------|----------------------|
| **Gobernar (GV)** | Política de threat modeling, gate de aprobación de seguridad, clasificación de datos, proceso de aceptación de riesgo. |
| **Identificar (ID)** | Inventario de activos y datos, IAM Access Analyzer, SBOM de dependencias. |
| **Proteger (PR)** | Mínimo privilegio + MFA, segmentación de red, Secrets Manager + KMS, WAF, hardening de contenedores. |
| **Detectar (DE)** | SIEM centralizado, GuardDuty, correlación de VPC Flow/CloudTrail, UEBA, reglas de fraude. |
| **Responder (RS)** | Runbooks de IR, alertamiento automatizado, grabación de sesión para forense, revocación break-glass. |
| **Recuperar (RC)** | RDS Multi-AZ, backups inmutables (S3 Object Lock), planes de restauración y rollback probados. |

### 3. Matriz de Priorización

La priorización sigue la fórmula: **Riesgo = Probabilidad × Impacto / Esfuerzo de Remediación**, favoreciendo
los controles que cierran el mayor blast radius con el menor esfuerzo.

| Prioridad | Acción | Justificación |
|-----------|--------|---------------|
| **P1** | **IAM Mínimo Privilegio + MFA** | Base de la seguridad en AWS; alto impacto, AWS provee herramientas (IAM Access Analyzer) y cierra el radio de impacto más amplio. |
| **P2** | **Migración a Secrets Manager** | Riesgo activo y fácilmente explotable si logs/contenedores se comprometen. Baja fricción con servicios gestionados de AWS. |
| **P3** | **Segregación de ambientes (VPC/Red)** | Requiere planeación pero limita drásticamente el movimiento lateral. Debe atenderse antes de escalar cargas. |
| **P4** | **Logging centralizado / SIEM** | Habilita capacidades de detección y respuesta. Sin él, las brechas pueden pasar desapercibidas por meses. |
| **P5** | **Gates de seguridad en CI/CD (SCA/SAST)** | Evita que nuevas vulnerabilidades entren al código base. Quick wins con GitHub Advanced Security o GitLab Secure. |
| **P6** | **Proceso formal de threat modeling** | Cambio cultural y de proceso; previene deuda futura pero no remedia la exposición actual. |
| **P7** | **Minimización de datos en API** | Corrección táctica que se realiza en paralelo con los sprints de desarrollo para reducir la fuga de datos. |

#### SLAs de Remediación Sugeridos

| Severidad | SLA de remediación | Ejemplos |
|-----------|--------------------|----------|
| **Crítica** | 24–72 horas | AuthN faltante en endpoint sensible, CVE crítica expuesta a internet. |
| **Alta** | 7–14 días | S3 con permisos excesivos, exposición de PII en API. |
| **Media** | 30 días | Headers inseguros, falta de MFA en admin no productivo. |
| **Baja** | 90 días / backlog | Dependencia vulnerable en herramienta interna no expuesta. |

### 4. Arquitectura Zero Trust para Acceso a Aplicaciones e Infraestructura

#### Principios (basados en NIST SP 800-207)
1. **Nunca confiar, siempre verificar** — Toda petición se autentica y autoriza, sin importar su origen.
2. **Mínimo privilegio** — Acceso mínimo necesario, acotado en el tiempo (JIT) siempre que sea posible.
3. **Asumir la brecha (assume breach)** — Segmentar cargas para que un solo compromiso no se propague.
4. **Decisión de acceso dinámica** — El acceso depende de identidad, postura del dispositivo, contexto y riesgo evaluado por un motor de políticas (PDP/PEP).

#### Arquitectura Propuesta

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Web Frontend  │     │   App Móvil     │     │  Portal Admin   │
│  (CloudFront)   │     │   (API Gateway) │     │  (IAM Identity  │
└────────┬────────┘     └────────┬────────┘     │   Center + MFA) │
         │                       │              └────────┬────────┘
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │      AWS WAF / ALB       │
                    │   (TLS 1.3, Rate Limit)  │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │     Amazon API Gateway   │
                    │  (AuthN: Cognito/OIDC)   │
                    │  (AuthZ: scopes/Lambda)  │
                    └────────────┬────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                  │
    ┌─────────▼────────┐ ┌───────▼─────┐ ┌──────────▼─────┐
    │   ECS / EKS      │ │   AWS       │ │   Amazon S3    │
    │  (Aplicación)    │ │  Secrets    │ │  (Documentos)  │
    │  IRSA / IAM Roles│ │  Manager    │ │ Bucket Policies│
    │  Security Groups │ │  + AWS KMS  │ │  + Cifrado     │
    └─────────┬────────┘ └─────────────┘ └────────────────┘
              │
    ┌─────────▼────────┐
    │   Amazon RDS     │
    │  (BD Gestionada) │
    │  Cifrado +       │
    │  Subred Privada  │
    └──────────────────┘
```

#### Componentes Clave Zero Trust

| Capa | Control | Tecnología / Método |
|------|---------|---------------------|
| **Identidad** | Autenticación fuerte + MFA | Amazon Cognito (usuarios), IAM Identity Center (admins), MFA por hardware/WebAuthn. |
| **Dispositivo** | Confianza y postura del dispositivo | MDM móvil; identidad de dispositivo basada en certificados; verificación de postura. |
| **Red** | Microsegmentación | VPCs por ambiente; subredes privadas; Security Groups con reglas explícitas allow-only. |
| **Aplicación** | mTLS + autenticación de servicio | AWS App Mesh / Istio con mutual TLS; IRSA para acceso a APIs de AWS a nivel de pod. |
| **Datos** | Cifrado en reposo y en tránsito | TLS 1.3 en tránsito; AWS KMS en reposo; tokenización de PII / datos financieros. |
| **Acceso Admin** | Sin SSH directo / sin VPN | AWS Systems Manager Session Manager; AWS PrivateLink para endpoints administrativos. |
| **Monitoreo** | Analítica de comportamiento + alertas | Amazon GuardDuty; SIEM con UEBA; detección de anomalías en patrones de acceso. |
| **Motor de Políticas** | Decisión de acceso dinámica (PDP/PEP) | Evaluación continua de identidad + postura + contexto; re-autenticación ante señales de riesgo. |

---

## Punto 2. AppSec / Threat Modeling — "Transferencia Rápida"

### 5. Principales Amenazas

| ID | Amenaza | Actor de Amenaza | Impacto de Negocio |
|----|---------|------------------|--------------------|
| T1 | Ejecución de transferencia no autorizada | Atacante con sesión robada | Pérdida financiera directa |
| T2 | Manipulación de la cuenta destino | Atacante con account takeover | Fondos desviados a cuentas del atacante |
| T3 | Automatización / abuso de transferencias | Botnet / defraudador | Vaciado rápido de fondos; daño reputacional |
| T4 | Replay de transacción / MitM | Atacante a nivel de red | Transacciones duplicadas o interceptadas |
| T5 | Acceso no autorizado al histórico | Atacante explotando IDOR/BOLA | Fuga de privacidad; violación regulatoria (GDPR/local) |
| T6 | Phishing / ingeniería social | Atacante externo | Robo de credenciales que habilita fraude de transferencia posterior |
| T7 | Inyección de notificaciones fraudulentas | Actor de spam/fraude | Confusión del usuario; erosión de confianza |

### 6. Vulnerabilidades Comunes por Capa

**Capa Web**
- XSS (Almacenado/Reflejado) vía campos de alias o memo al registrar cuentas frecuentes.
- CSRF en endpoints de "agregar cuenta frecuente" o "confirmar transferencia" sin tokens adecuados.
- IDOR / BOLA en histórico de transferencias: cambiar `?user_id=123` expone registros de otros usuarios.
- Referencias directas inseguras a objetos (IDOR) en enlaces de descarga de comprobantes.

**Capa Móvil**
- Almacenamiento inseguro de tokens: JWTs en `SharedPreferences` en vez de Keychain/Keystore.
- Falta de certificate pinning que permite MitM con certificados falsos.
- Manejo inseguro de deep-links: `fincloud://transfer?to=CUENTA_ATACANTE&amount=1000`.
- Detección de root/jailbreak insuficiente o fácil de evadir.

**Capa API**
- BOLA: los endpoints no verifican que `account_id` o `transfer_id` pertenezcan al usuario autenticado.
- Exposición excesiva de datos: respuestas con números de cuenta completos, saldos o documentos de identidad.
- Mass assignment: el atacante inyecta campos JSON extra (p. ej. `isAdmin`, `bypassLimit`).
- Autenticación rota: firma JWT débil, falta de expiración de token o tokens reutilizables (replay).
- Falta de rate limiting en endpoints de transferencia que habilita fuerza bruta o abuso automatizado.

### 7. Controles Preventivos y Detectivos (Pre-Producción)

**Controles Preventivos**

| Control | Detalle |
|---------|---------|
| Autenticación fuerte | OAuth 2.0 + PKCE en móvil; JWTs de corta duración; rotación de refresh tokens. |
| Autorización (BOLA/ABAC) | Verificación de propiedad en cada petición: "¿Este `account_id` pertenece al `sub` del JWT?" |
| Validación de entradas | Whitelist de campos aceptados; sanear alias; validar formato de cuenta destino contra registro bancario externo. |
| Límites y Rate Limiting | Límites diarios por usuario; controles de velocidad; throttling por IP; CAPTCHA al registrar cuenta frecuente. |
| Step-Up Authentication | Biometría o OTP push para transferencias a terceros o por encima de umbrales configurables. |
| Device Binding | Asociar sesiones a huellas de dispositivo; alertar y re-autenticar en dispositivos nuevos. |
| Filtrado / enmascaramiento de salida | Devolver cuentas enmascaradas (`****1234`); nunca devolver documentos completos. |
| Certificate Pinning | Forzar pinning en la app móvil para prevenir CA falsas / MitM. |

**Controles Detectivos**

| Control | Detalle |
|---------|---------|
| Reglas de fraude en tiempo real | Marcar transacciones por anomalías de monto, geolocalización inusual, beneficiarios nuevos o viaje imposible. |
| Alertas SIEM | Alertar secuencias: múltiples fallos de auth → auth exitosa → transferencia inmediata a beneficiario nuevo. |
| UEBA | Perfilar comportamiento normal; alertar desviaciones (horario, monto, cambio de dispositivo). |
| Logs de auditoría inmutables | Ledger de transacciones append-only (Amazon QLDB o S3 Object Lock + CloudTrail) para no repudio. |
| Cuentas canario / honeypot | Registrar cuentas señuelo; cualquier transferencia hacia ellas dispara alerta crítica inmediata. |

### 8. Actividades de Secure SDLC

| Fase | Actividad | Responsables |
|------|-----------|--------------|
| **Requerimientos** | Definir requisitos de seguridad y de abuso; umbrales de riesgo aceptable y necesidades de cumplimiento. | Producto + Seguridad |
| **Diseño** | **Threat Modeling obligatorio** (STRIDE) para Transferencia rápida; revisión de arquitectura de seguridad. | Seguridad + Arquitecto |
| **Desarrollo** | Capacitación en codificación segura (OWASP Top 10 / ASVS); checklist interno de seguridad. | Ingeniería |
| **Código** | **SAST** en cada PR; **SCA** de dependencias; hooks de pre-commit para detección de secretos (GitLeaks/TruffleHog). | DevSecOps |
| **Pruebas** | **DAST** contra staging; pentest dedicado a los flujos de transferencia; fuzzing de entradas de API. | Seguridad + QA |
| **Pre-Release** | Gate de aprobación de seguridad; revisión de configuración; escaneo de vulnerabilidades de la imagen. | Seguridad |
| **Despliegue** | Solo artefactos firmados; despliegue automatizado con gates de seguridad; plan de rollback validado. | DevOps |
| **Operación** | Programa de Divulgación de Vulnerabilidades (VDP) / Bug Bounty; runbooks de respuesta a incidentes; retrospectivas post-incidente. | Seguridad + SRE |

---

## Punto 3. Gestión y Priorización de Vulnerabilidades

### Modelo de Priorización

Se prioriza con: **Riesgo = Exposición × Explotabilidad × Impacto**, enriquecido con inteligencia de amenazas.
Cada hallazgo se evalúa con:
- **Exposición:** ¿Expuesto a internet, red interna o solo insiders?
- **Explotabilidad:** CVSS v3.1 + **EPSS** (probabilidad de explotación) + presencia en **CISA KEV** + existencia de PoC público.
- **Impacto:** Sensibilidad del dato (PII/PAN), impacto financiero/regulatorio y facilidad de compensación con otros controles.

### 9. Hallazgos Priorizados (1 = mayor prioridad)

| Rank | Hallazgo | Severidad | Justificación |
|------|----------|-----------|---------------|
| **1** | **High: Autenticación insuficiente en endpoint sensible** | Crítico (operacional) | La ausencia de autenticación es una falla de diseño; la explotación es trivial y el impacto inmediato e irreversible (pérdida de datos/fondos). |
| **2** | **Crítica: Vulnerabilidad de librería en componente expuesto a internet** | Crítico (técnico) | Superficie de ataque pública + CVE conocida = alta probabilidad de explotación automatizada (RCE o brecha de datos). |
| **3** | **Bucket S3 con permisos excesivos** | Alto | Aun sin evidencia de acceso externo, es descubrible y representa alto riesgo regulatorio/reputacional si se filtran datos. |
| **4** | **Endpoint API devuelve el número de documento completo en respuestas internas** | Medio-Alto | Fuga de PII; incumple GDPR/normativa local; habilita fraude de identidad e ingeniería social. |
| **5** | **Falta de MFA en accesos administrativos no productivos** | Medio | Los ambientes no productivos suelen tener datos similares a producción; un admin comprometido habilita pivoteo y exfiltración. |
| **6** | **Medium: Headers inseguros en portal público** | Medio | Aumenta riesgo de XSS/clickjacking, pero el impacto se mitiga parcialmente con navegadores modernos y controles en capas. |
| **7** | **Dependencia vulnerable en herramienta interna no expuesta a internet** | Bajo | Sin superficie de ataque externa; riesgo limitado a amenaza interna o requiere compromiso previo de la red. |

### 10. Primera Remediación: Autenticación Insuficiente

La autenticación insuficiente en un endpoint sensible se remedia primero porque es una **falla que ningún control
compensatorio cubre**. Ninguna regla de WAF, dashboard de monitoreo o capa de cifrado puede compensar la ausencia
de autenticación en una función de negocio sensible. Suele ser una corrección rápida (agregar o corregir el
middleware de autorización) y tiene el mayor impacto directo de negocio: acceso no autorizado a datos de clientes
u operaciones financieras.

La vulnerabilidad crítica de librería es un segundo muy cercano; sin embargo, puede requerir pruebas de regresión
y análisis de compatibilidad de dependencias, mientras que los huecos de autenticación suelen parchearse en horas.

### 11. Información Adicional Requerida

Para refinar la priorización se necesita:

1. **Vector CVSS v3.1 y score EPSS** de cada CVE para entender la probabilidad de explotación.
2. **Inteligencia de amenazas**: ¿La CVE está en CISA KEV? ¿Hay exploits públicos (Metasploit, PoC)?
3. **Mapeo de impacto de negocio**: ¿Qué datos o funciones específicas expone cada endpoint vulnerable?
4. **Contexto de arquitectura de red**: ¿El endpoint sin autenticación es público a internet o está tras VPN/private link?
5. **Logs de acceso a S3 (CloudTrail / S3 Server Access Logs)**: para determinar si hubo enumeración o accesos no autorizados.
6. **Restricciones de SLA / RTO**: ¿Con qué rapidez se puede desplegar un parche sin romper acuerdos de nivel de servicio?
7. **Clasificación de datos**: ¿El bucket S3 o la herramienta interna contienen PII, PAN o secretos de autenticación?
8. **Alcance del admin**: ¿Qué permisos tienen las cuentas admin no productivas? ¿Pueden acceder a producción vía roles cross-account?

### 12. Justificación ante Desarrollo y Liderazgo

**Ante Desarrollo (justificación técnica)**

> "El endpoint sensible sin autenticación es un defecto de seguridad P0. No es un tema de hardening de configuración;
> es un control de seguridad ausente que permite a cualquiera en la red acceder a funcionalidad crítica de negocio.
> No podemos compensarlo con monitoreo ni reglas de WAF: debe corregirse antes que cualquier otro trabajo de features.
> La librería crítica expuesta es igual de urgente desde la perspectiva de amenaza externa; programaremos la
> actualización este sprint y correremos pruebas de regresión automatizadas para asegurar compatibilidad. Los demás
> ítems son importantes pero pueden paralelizarse sin bloquear releases."

**Ante Liderazgo / Ejecutivos (justificación de riesgo de negocio)**

> "Tenemos dos hallazgos que representan riesgo regulatorio y financiero inmediato. Un endpoint sin autenticación en
> una plataforma fintech podría permitir acceso no autorizado a cuentas de clientes o movimiento de fondos, resultando
> en pérdida financiera directa, sanciones regulatorias y multas (GDPR/normativa local). Una vulnerabilidad crítica en
> un componente expuesto a internet es escaneada activamente por atacantes en todo el mundo; el costo de remediarla es
> mínimo frente al costo de una investigación de brecha, honorarios legales y daño reputacional. Corregir estos dos
> ítems esta semana protege nuestra licencia para operar y la confianza del cliente. El backlog restante se atiende con
> la cadencia normal de sprints sin impactar la velocidad de entrega."

---

*Fin del documento*
