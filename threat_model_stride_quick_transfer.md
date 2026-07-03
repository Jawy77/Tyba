# Threat Model: Funcionalidad "Transferencia Rápida"
## Metodología: STRIDE
## Objeto de Evaluación (ToE): Transferencia Rápida (Web, Móvil, API)

---

### Diagrama de Flujo de Datos (DFD) Simplificado

```
┌──────────┐     ┌──────────┐     ┌──────────────┐     ┌──────────────┐
│  Usuario │────▶│  Web /   │────▶│  API Gateway │────▶│   Backend    │
│ (Actor)  │     │  Móvil   │     │ (Auth/Rate)  │     │ (Transf.     │
└──────────┘     └──────────┘     └──────────────┘     │  rápida)     │
                                                        └──────┬───────┘
                    ┌──────────────┐     ┌──────────────┐      │
                    │  Svc Notif   │◀────│   Motor de   │◀─────┘
                    │ (Push/Email) │     │  Transferenc.│
                    └──────────────┘     └──────┬───────┘
                                                │
                          ┌──────────────┐      │      ┌──────────────┐
                          │  BD Cuentas  │◀─────┘─────▶│  BD Histórico│
                          │ (Destinos)   │            │ (Transacc.)  │
                          └──────────────┘            └──────────────┘
```

### Fronteras de Confianza (Trust Boundaries)

| # | Frontera | Riesgo principal al cruzarla |
|---|----------|------------------------------|
| TB1 | Internet ↔ Web/Móvil | Manipulación del cliente, MitM, bots. |
| TB2 | Cliente ↔ API Gateway | Autenticación/autorización, rate limiting, validación de entradas. |
| TB3 | API Gateway ↔ Backend | Autorización de servicio, mass assignment, BOLA. |
| TB4 | Backend ↔ Bases de Datos | Mínimo privilegio, cifrado, integridad de datos. |
| TB5 | Backend ↔ Servicio de Notificaciones | Inyección de notificaciones, fuga de datos por canales externos. |

---

### Análisis STRIDE

#### 1. Spoofing (Suplantación)
| Amenaza | Descripción | Riesgo | Mitigación |
|---------|-------------|--------|------------|
| T-S1 | Atacante suplanta a un usuario legítimo con credenciales o token de sesión robado. | Alto | MFA (TOTP / Biometría / Push); JWTs de corta duración; device binding; detección de anomalías en login. |
| T-S2 | Atacante suplanta la app móvil reempaquetándola o usando certificados comprometidos. | Medio | Certificate pinning; app attestation (Play Integrity / App Attest); ofuscación de código. |
| T-S3 | Suplantación de admin/operador vía credenciales no productivas comprometidas. | Alto | MFA obligatorio para todo acceso admin; proveedores de identidad separados; elevación de privilegios JIT. |

#### 2. Tampering (Manipulación)
| Amenaza | Descripción | Riesgo | Mitigación |
|---------|-------------|--------|------------|
| T-T1 | Atacante modifica el monto o la cuenta destino en tránsito. | Alto | TLS 1.3 en todo; firma de peticiones (HMAC); idempotency keys; logs de auditoría inmutables. |
| T-T2 | Atacante manipula la lista de "cuentas frecuentes" para desviar fondos. | Alto | Verificaciones de integridad (checksums/HMAC) en cuentas frecuentes; autorizar cada transferencia de forma independiente. |
| T-T3 | Manipulación de base de datos para alterar saldos o histórico. | Alto | Cifrado en reposo (KMS); Database Activity Monitoring (DAM); credenciales de BD de mínimo privilegio. |

#### 3. Repudiation (Repudio)
| Amenaza | Descripción | Riesgo | Mitigación |
|---------|-------------|--------|------------|
| T-R1 | El usuario niega haber iniciado una transferencia. | Medio | No repudio vía logs de auditoría inmutables y firmados (QLDB / S3 Object Lock); comprobantes detallados de transacción. |
| T-R2 | El operador niega una acción administrativa. | Medio | Grabación de sesiones admin (Session Manager); logging centralizado en CloudTrail con validación de integridad. |

#### 4. Information Disclosure (Divulgación de Información)
| Amenaza | Descripción | Riesgo | Mitigación |
|---------|-------------|--------|------------|
| T-I1 | La API sobreexpone números de cuenta, documentos o saldos completos. | Alto | Esquemas de respuesta estrictos (minimización de datos); filtrado de salida / control de acceso a nivel de campo; enmascaramiento. |
| T-I2 | Los logs capturan datos sensibles (PAN, contraseñas). | Alto | Reglas de saneamiento de logs; logging estructurado con redacción de PII; acceso restringido a logs. |
| T-I3 | La app móvil filtra datos por capturas de pantalla, backups o portapapeles. | Medio | FLAG_SECURE (Android); bloquear capturas; limpiar portapapeles tras pegar; almacenamiento local cifrado. |

#### 5. Denial of Service (Denegación de Servicio)
| Amenaza | Descripción | Riesgo | Mitigación |
|---------|-------------|--------|------------|
| T-D1 | Un script automatizado satura el endpoint de transferencias agotando recursos. | Medio | Rate limiting por usuario/IP; CAPTCHA en acciones de riesgo; auto-scaling; reglas rate-based en WAF. |
| T-D2 | El atacante bloquea la cuenta del usuario con repetidos fallos de step-up auth. | Medio | Bloqueo de cuenta con backoff exponencial; notificar al usuario por canal out-of-band; monitoreo de fraude. |

#### 6. Elevation of Privilege (Elevación de Privilegios)
| Amenaza | Descripción | Riesgo | Mitigación |
|---------|-------------|--------|------------|
| T-E1 | Atacante accede al histórico de transferencias de otro usuario vía IDOR/BOLA. | Alto | ABAC: verificar propiedad en cada acceso a objeto; usar identificadores opacos (UUIDs). |
| T-E2 | Atacante eleva privilegios vía mass assignment (p. ej. agregar `isAdmin`). | Alto | DTOs estrictos / whitelisting; rechazar campos desconocidos; separar APIs de admin y de usuario. |
| T-E3 | Un servicio backend comprometido asume el rol de otro servicio. | Medio | mTLS servicio-a-servicio + SPIFFE/SPIRE o roles IAM por carga; políticas de red. |

---

### Resumen de Controles Clave por Categoría STRIDE

| Categoría | Control Principal |
|-----------|-------------------|
| **Spoofing** | MFA + Device Binding + App Attestation |
| **Tampering** | TLS 1.3 + Firma HMAC + Logs Inmutables |
| **Repudiation** | Audit Trail Firmado + Grabación de Sesión |
| **Information Disclosure** | Minimización de Datos + Enmascaramiento + Redacción de Logs |
| **Denial of Service** | Rate Limiting + Auto-scale + WAF |
| **Elevation of Privilege** | Verificaciones ABAC/BOLA + mTLS + Whitelisting de entradas |

---

*Documento generado como parte del entregable de Threat Modeling para FinCloud Invest.*
