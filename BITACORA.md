# 📋 BITÁCORA TQSC v2.0 — Registro de cambios

## [2.0.1] — 2026-07-28 — Auditoría de honestidad técnica

### Corregido — Bugs críticos (23 bugs en 23 archivos)
- secure_storage.py: corrupción de ciphertext por separador \n → base64
- vuln_mgmt.py: funciones faltantes y duplicadas → implementadas
- mfa.py: fallback inseguro (string reversal) → RuntimeError
- sysmon_edr.py: XML parsing crash → root wrapper
- hud_display.py: clase duplicada eliminaba POST endpoints → eliminada
- ipc_red.py + supervised_main.py: hash() no determinista → hashlib.sha256
- audit.py + auth.py: HMAC truncado → completo (256 bits)
- Y 14 correcciones más de seguridad, compatibilidad y calidad

### Corregido — Honestidad técnica
- Docstrings actualizados para reflejar implementación real
- Eliminadas menciones falsas a BERT, GNN, LSTM, PPO, LoRA, CUDA kernels
- Añadidos disclaimers en documentación de arquitectura
- SyscallMonitor: reconocido como monitor de procesos, no interceptor de syscalls
- GeoNoise: reconocido como generador pseudo-aleatorio, no geolocalización real
- Quantum: reconocido como criptografía clásica

## [2.0.0] — 2026-07-10 — Ciclo de desarrollo completo

### Añadido — Núcleo de Seguridad
- **SIEM Core** (`utils/siem_core.py`): 23 reglas de correlación, EventStore time-series, ingesta externa
- **EDR Filesystem** (`utils/fs_monitor.py`): Monitoreo de directorios críticos, snapshots SHA256
- **EDR Procesos** (`utils/proc_analyzer.py`): Árbol de procesos, detección LOTL, memoria inyectada
- **EDR Registro** (`utils/registry_monitor.py`): 9 claves de persistencia Windows, diff automático
- **PacketWatch** (`utils/packet_watch.py`): Conexiones de red, port scan, DNS DGA detection
- **FirewallManager** (`utils/firewall.py`): netsh (Windows) / iptables (Linux)
- **IDSEngine** (`utils/ids.py`): 5 firmas de ataque, respuesta automática
- **VulnManager** (`utils/vuln_mgmt.py`): CVE scanning, 10 CIS benchmarks, pip audit

### Añadido — Autenticación y Compliance
- **AuthManager** (`utils/auth.py`): RBAC admin/operator/viewer + account lockout (5→15min)
- **MFA** (`utils/mfa.py`): TOTP RFC 6238, secretos cifrados con CA cert
- **AuditTrail** (`utils/audit.py`): Cadena HMAC blockchain-style, thread-safe
- **IdentityManager** (`utils/identity.py`): Certificados por núcleo, rotación SC-12, baseline CM-2
- **IncidentEngine** (`utils/incident.py`): Playbooks NIST IR-4, 5 defaults

### Añadido — Auto-diagnóstico
- **Doctor TQSC** (`utils/doctor.py`): 10 diagnósticos por núcleo, 6 reparaciones automáticas

### Añadido — Infraestructura
- **BackupManager** (`utils/backup.py`): Backup/Restore con checksum SHA256
- **SyslogForwarder** (`utils/siem.py`): RFC 3164, AlertEngine multicanal

### Modificado — Núcleos existentes
- **HUD** (`hud/hud_display.py`): API Key auth + Rate limiting (30/min) + Content-Type validation + mTLS + endpoints: /api/login, /api/audit, /api/mfa, /api/siem
- **main.py**: Integración SIEM + EDR + Doctor + Firewall + VulnManager
- **run.py**: SIGTERM handler + auto-generación certificados TLS
- **config.py**: DATA_DIR configurable via TQSC_HOME
- **Dockerfile**: Multi-stage, no-root, tini, healthcheck, chown

### Añadido — Documentación
- **LIMITACIONES_ML.md**: Transparencia: no hay IA autoevolutiva, solo 13 RandomForest estáticos sobre dataset sintético
- **Benchmark**: `tools/benchmark.py` — SIEM 3,798 evts/s, auditoría 692/s, auth 29,796/s
- **Bitácora**: `BITACORA.md` — registro completo de cambios

### Corregido — Auditorías Red Team
- **Redteam inicial**: 48 vulnerabilidades → 48 fix
- **Redteam agresivo #1**: 12 vulns → 12 fix
- **Redteam agresivo #2**: 12 vulns → 12 fix
- **CIA audit**: 8 vulns → 8 fix
- **Anonymous audit**: 12 vulns → 12 fix
- **Backup path traversal (Gemini)**: `relative_to()` mutaba ruta a relativa → `startswith()` mantiene absoluta
- **Default credentials**: ahora BLOQUEAN con RuntimeError (no solo advierten)
- **Rust bridge**: +1 función (`firewall_block`) → 4 funciones total
- **ML**: +validación cruzada 5-fold con scores guardados
- **Total**: 104 vulnerabilidades → 104 corregidas/aceptadas

### Mejoras de seguridad
- SHA256→HMAC en GhostMemoryZone, NodeChallenge, IPC
- TQSC_TEST lazy evaluation en 5 módulos
- Secretos globales → per-instancia
- Singletons thread-safe (double-checked locking)
- Path traversal bloqueado (decode recursivo + normalize)
- TOCTOU eliminado (read directo sin exists())
- Content-Type validado, payload limitado (64KB)
- Bare `except:` eliminados (tipos específicos)
- Docker no-root + cap_drop ALL

### Cumplimiento normativo
- PCI DSS: 9/9 requisitos (AES-256-GCM, mTLS, RBAC, MFA, auditoría)
- NIST 800-53: AC-2, AC-7, AU-2, CM-2, IR-4, SA-12, SC-12
- Docker hardening: 18 problemas resueltos

### Métricas finales
- Líneas de código: ~35,000
- Módulos: 25+ archivos en tqsc/
- Núcleos: 9/9
- Tests stress: 9/10
- Vulnerabilidades corregidas: 104
- **Benchmark**: SIEM 3,798 evts/s · Auditoría 692/s · Auth 29,796/s
  Crypto AES 0.009ms · EventBus 37,193 evts/s · Memoria 32.6MB
- **Documentación técnica**: `BITACORA.md` + `LIMITACIONES_ML.md` + `tools/benchmark.py`
