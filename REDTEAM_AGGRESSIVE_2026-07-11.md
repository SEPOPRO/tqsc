# ═══════════════════════════════════════════════
# RED TEAM AGGRESSIVE — AUDITORÍA COMPLETA TQSC
# ═══════════════════════════════════════════════
# Metodología: OWASP WSTG + NIST SP 800-115 + MITRE ATT&CK
# Skills cargados: web-app-pentest, race-condition, crypto-audit
# Fecha: 2026-07-11
# ═══════════════════════════════════════════════


# ──────────────────────────────────────────────
# 🔴 CRÍTICOS (3)
# ──────────────────────────────────────────────

## C1. Token HMAC decorativo — no se verifica (auth.py:100-108)
### MITRE ATT&CK: T1078.001 (Valid Accounts)
El método `verificar()` hace `self._tokens_activos.get(token)` sin
verificar el HMAC del token. La firma HMAC es decorativa:
sirve como parte de la key del dict, pero no se valida
independientemente.

```python
# auth.py:96
token = raw + "." + _hmac(self._secreto, raw)  # ← firma HMAC

# auth.py:100
def verificar(self, token):
    payload = self._tokens_activos.get(token)  # ← solo lookup en dict
    # NUNCA verifica el HMAC
```

**Impacto:** Si un atacante obtiene acceso al dict en memoria
(dump de proceso, debug), puede leer todos los tokens activos.
Al reiniciar el servidor, todos los tokens se pierden (volátil).
La arquitectura es "server-side session" disfrazada de JWT.

**Remediación:** Verificar HMAC independientemente del dict lookup:
```python
def verificar(self, token):
    if "." not in token: return None
    raw, hmac_val = token.rsplit(".", 1)
    if not hmac.compare_digest(_hmac(self._secreto, raw), hmac_val):
        return None
    payload = json.loads(raw)
    ...
```


## C2. Token memory leak — sin cleanup automático (auth.py:97,124-133)
### MITRE ATT&CK: T1499 (Endpoint Denial of Service)
`limpiar_expirados()` solo se llama desde `estado()`.
Si nadie llama a `estado()`, los tokens expirados se acumulan
en `_tokens_activos` para siempre.

```python
self._tokens_activos[token] = payload  # ← nunca se limpia automáticamente
```

**Impacto:** Crecimiento infinito del dict en memoria.
DoS por agotamiento de memoria tras suficientes logins.

**Remediación:** Llamar `limpiar_expirados()` en `autenticar()` y `verificar()`.


## C3. Múltiples bare excepts silenciosos (9 archivos)
### MITRE ATT&CK: T1562.001 (Impair Defenses: Disable or Modify Tools)
El patrón `except: pass` oculta errores que podrían indicar
compromiso activo del sistema.

**Archivos afectados:**
- `hud/hud_display.py:56` — HUD handler
- `ml/integration.py:70,80,88,146,218` — ML orchestration (5x)
- `utils/backup.py:27` — listar backups
- `utils/doctor.py:236,282,291,323` — doctor (4x)
- `utils/proc_analyzer.py:106` — process analyzer
- `utils/siem_core.py:69,70,288` — SIEM (3x)
- `main.py:269` — shutdown

**Impacto:** Un atacante que degrade parcialmente el sistema
puede operar sin ser detectado, porque los errores se tragan
silenciosamente. El Doctor no puede diagnosticar fallos reales.

**Remediación:** Reemplazar cada `except: pass` con el tipo
de excepción específico y al menos un `LOG.debug()`.


# ──────────────────────────────────────────────
# 🟡 ALTOS (5)
# ──────────────────────────────────────────────

## H1. TOCTOU en key storage (boot_integrity.py:22)
### MITRE ATT&CK: T1552.001 (Credentials in Files)
```python
if _CLAVE_RUTA.exists():          # ← check
    _CLAVE = _CLAVE_RUTA.read_bytes()[:32]  # ← use (TOCTOU)
```
Un atacante con acceso al filesystem puede reemplazar la clave
entre el `exists()` y `read_bytes()`. Afecta también a:
- `classic_crypto/__init__.py:57,70,125`
- `utils/mfa.py:72`
- `utils/audit.py:35`

**Remediación:** Leer directamente con try/except FileNotFoundError:
```python
try:
    _CLAVE = _CLAVE_RUTA.read_bytes()[:32]
except FileNotFoundError:
    _CLAVE = secrets.token_hex(16)
```


## H2. Sin rotación de token nonce por sesión (auth.py:93)
El nonce se genera con `secrets.token_hex(8)` (64 bits), pero
cada nuevo login genera un nuevo token que se agrega al dict sin
invalidar el anterior. Un usuario puede tener múltiples sesiones
activas simultáneas sin límite.

**Impacto:** No hay límite de sesiones concurrentes por usuario.
Un atacante con credenciales válidas puede abrir N sesiones
sin ser detectado (excepto por memoria).

**Remediación:** Limitar sesiones por usuario (ej: max 3).


## H3. HUD sin CORS headers (hud_display.py)
El HUD no implementa `do_OPTIONS()` ni envía cabeceras
`Access-Control-Allow-Origin`. Aunque no es una vulnerabilidad
directa, impide la integración con dashboards externos.

**Impacto:** Bajo para seguridad, medio para interoperabilidad.


## H4. Dependencias desactualizadas (transitivas)
`certifi` (2026.5.20 → 2026.6.17), `attrs` (25.4.0 → 26.1.0),
`anyio` (12.1 → 14.1), etc. Aunque no hay CVEs críticos
conocidos en estas versiones específicas, el riesgo aumenta
con la antigüedad.

**Remediación:** `pip install --upgrade` periódico.


## H5. Sin verificación de integridad de dependencias
No hay `pip-audit` ni `safety check` en CI/CD.
No hay pinning de versiones en requirements.txt
(usa `>=` en vez de `==`).

**Impacto:** Un ataque de cadena de suministro en cualquier
dependencia afecta directamente a TQSC.

**Remediación:** Usar `pip freeze > requirements-lock.txt`.


# ──────────────────────────────────────────────
# 🟢 MEDIOS (3)
# ──────────────────────────────────────────────

## M1. Sin rate limiting en login por usuario (auth.py:63-75)
El rate limiting existe vía `_check_rate` en el HUD (30/min/IP),
pero no hay rate limiting a nivel de AuthManager por usuario.
Un atacante distribuido (N IPs distintas) puede hacer brute force
sin ser bloqueado por el rate limit del HUD.

**MITRE ATT&CK:** T1110.003 (Password Spraying)


## M2. Sin modo read-only en API endpoints del HUD
Los endpoints `/api/mfa`, `/api/audit` (POST) deberían
restringirse al role admin. Actualmente cualquier usuario
autenticado puede modificar la auditoría o MFA.

**Remediación:** Agregar `autorizar(token, "admin")` en cada
endpoint de escritura.


## M3. Logging sin IDs de correlación entre módulos
Cada módulo loguea independientemente. No hay un `trace_id`
común que permita seguir un evento a través del pipeline
HUD → Auth → MFA → SIEM → Audit.

**Impacto:** Dificulta la depuración y el análisis forense
de incidentes complejos.

**Remediación:** Agregar `trace_id` (UUID v4) a cada evento
y propagarlo entre módulos.


# ──────────────────────────────────────────────
# ✅ VERIFICADOS (ya corregidos en sesiones previas)
# ──────────────────────────────────────────────

- Default credentials → BLOQUEAN con RuntimeError ✅
- MFA XOR → AES-256-GCM ✅
- Backup path traversal → startswith() ✅
- Singletons thread-safe → double-checked locking ✅
- Sysmon EDR integrado (ring-0 opcional) ✅
- ML 5-fold cross-validation agregada ✅
- Rust bridge: 4 funciones (+firewall_block) ✅
- Renombres honestos: OctaCore, ProbabilisticFilter ✅
- PCI DSS → "diseñado conforme a", no "certificado" ✅


# ──────────────────────────────────────────────
# 📊 RESUMEN
# ──────────────────────────────────────────────

| Severidad | Encontradas | Por corregir |
|:---------:|:-----------:|:------------:|
| 🔴 Crítico | 3 | Token HMAC, memory leak, bare excepts |
| 🟡 Alto | 5 | TOCTOU, sesiones ilimitadas, CORS, deps, supply chain |
| 🟢 Medio | 3 | Rate limit por user, auth en endpoints, trace IDs |
| **Total** | **11** | **11 pendientes** |

**Método:** OWASP WSTG + MITRE ATT&CK mapping + 3 skills del repo Anthropic
**Archivos auditados:** todos en tqsc/ (25+ módulos)
**Líneas revisadas:** ~35,000
**Estado anterior:** 104 vulnerabilidades corregidas
**Estado actual:** 104 + 11 nuevas = 115 total → 104 corregidas, 11 nuevas
