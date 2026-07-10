# 🏗️ ARQUITECTURA TQSC v2.0 — DOCUMENTO COMPLETO
## Sistema de Defensa Cibernética Autónomo
### 9 Núcleos · 54+ Subnúcleos · ~15,000 Líneas · 12 Suites de Test · Rust Nativo

---

## 📐 DIAGRAMA DE ARQUITECTURA

```
                    ┌──────────────────────────────────────────────┐
                    │           SUPERVISOR (supervisor.py)          │
                    │  Watchdog multiproceso · Rate limit · mTLS   │
                    │  HUD Web (localhost:9090) · Event Bus         │
                    └──────┬───────┬───────┬───────┬───────┬───────┘
                           │       │       │       │       │
         ┌─────────────────┘       │       │       │       └─────────────────┐
         │         ┌───────────────┘       │       └───────────────┐         │
    ┌────┴────┐ ┌──┴───┐ ┌───────┴──┐ ┌───┴────┐ ┌──┴───┐ ┌──────┴────┐
    │IA CORE  │ │DEFEN │ │CLASSIC   │ │BLOCKCH │ │HONEY │ │ENTROPIA  │
    │OctaRCQ  │ │FÍSICA│ │CRYPTO    │ │AIN     │ │POT   │ │NoiseEng  │
    │18 subnúc│ │12 s/n│ │AES+GCM   │ │IPC real│ │30+   │ │Shannon   │
    │World ML │ │Rust  │ │Ed25519   │ │7 nodos │ │cmd   │ │DNS Shield│
    │Shadows  │ │native│ │HKDF      │ │mTLS    │ │ML    │ │          │
    └────┬────┘ └──┬───┘ └──────┬───┘ └───┬────┘ └──┬───┘ └──────┬────┘
         │         │            │         │         │            │
    ┌────┴────┐ ┌──┴───┐ ┌─────┴───┐ ┌────┴────┐
    │CORTEX  │ │PAZ   │ │MEMORIA  │ │GEONOISE │
    │Descong │ │Proto │ │Episódica│ │WiFi+OSM │
    │3 fases │ │Nonces│ │Watermark│ │Jitter   │
    │HMAC    │ │mTLS  │ │HMAC     │ │HMAC logs│
    └────────┘ └──────┘ └─────────┘ └─────────┘
```

### Infraestructura Base
```
┌─────────────────────────────────────────────────────────────┐
│                      INFRAESTRUCTURA                         │
├─────────────────────────────────────────────────────────────┤
│ Supervisor watchdog  │ Boot Integrity HMAC                   │
│ Secure Storage AES   │ Docker Compose (11 servicios)         │
│ mTLS entre servicios │ Rust native (tqsc_native v0.1.0)     │
│ 2 redes Docker:      │ World Model ML (13 cabezas sklearn)  │
│   tqsc_internal      │ HUD Web SOC (localhost:9090)         │
│   tqsc_exposed       │ Event Bus en vivo                    │
└─────────────────────────────────────────────────────────────┘
```

---

## 🧠 NÚCLEO 1: IA AUTOEVOLUTIVA (OctaRCQ-X8)
### Archivo: `core/octarcq.py`, `core/octa_nucleo.py`, `ia/__init__.py`
### Subnúcleos: 18 · Líneas: ~600

### Pipeline de Procesamiento (4 filtros cuánticos en orden aleatorio)
```
Evento → QuantumValidator → VeracitySynthesizer → PreImpactSynthesizer → ContextWeaver → OctaRCQ
```
- **8 octantes** de procesamiento en paralelo con sombras (shadows) para failover
- **CognitiveLoopDetector** — detecta ciclos degenerativos (ventana de 8, threshold 3)
- **MetaCoreAdjuster** — aísla núcleos con comportamiento degenerativo
- **IAJudicialInterna** — 13 reglas dinámicas, 4 categorías, voto ponderado
- **EthicalConsensusGate** — voto entre 3 agentes con pesos
- **PatternTransfuser** — transfiere aprendizaje entre octantes (con anti-envenenamiento)
- **MutationLogger** — registra todas las mutaciones con HMAC
- **World Model ML** — clasificación híbrida reglas + sklearn (13 cabezas)
- **GhostMemory** — memoria efímera por octante con HMAC

---

## 🛡️ NÚCLEO 2: DEFENSA FÍSICA
### Archivo: `defense/__init__.py`, `defense/syscall_monitor.py`, `defense/geonoise.py`
### Subnúcleos: 12 · Líneas: ~500

| Subnúcleo | Función | Implementación |
|-----------|---------|----------------|
| CPUUsageScanner | Monitoreo CPU | psutil + umbral configurable (80%) + ventana 60s |
| ProcessAffinityGuard | Aísla procesos | set affinity + verificación + rollback + historial |
| CacheDisruptor | Inyecta entropía | **Rust nativo** (VirtualAlloc) + 3 patrones variables |
| SyscallMonitor | Monitorea llamadas | **Rust nativo** (CreateToolhelp32Snapshot) |
| PIDSignatureMatcher | Detecta hotpatch | **Rust nativo** (ReadProcessMemory) |
| OpcodeInterruptionEngine | Detecta shellcode | 5 categorías de patrones + heurística frecuencias |
| HeatMapDifferentialShield | Anomalía térmica | Ventana 60s + correlación CPU/temp + std deviation |
| EntropyShield | Contramedidas activas | RAM noise, DNS tunneling checker, thermal injection |
| GeoNoiseTracker | Geolocalización | **WiFi real (netsh) + OSM Nominatim** + jitter 15% |
| DefenseCore | Orquestador | Inicia todos los módulos, reporta estado |
| **Rust bridge** | Fallback graceful | `native_bridge.py` → tqsc_native o Python ctypes |

---

## 🔐 NÚCLEO 3: CLASSIC CRYPTO (antes "Quantum")
### Archivo: `classic_crypto/__init__.py`
### Subnúcleos: 6 · Líneas: ~210

| Componente | Algoritmo | Fallback |
|------------|-----------|----------|
| KeyManager | HKDF-SHA256 (RFC 5869) + HMAC integridad | SHA256 directo |
| CifradorAES | AES-256-GCM | Error si no disponible |
| FirmaDigital | Ed25519 (PyNaCl) | HMAC-SHA256 |
| **Protección archivos** | chmod(read-only) | Regeneración automática |

---

## ⛓️ NÚCLEO 4: BLOCKCHAIN
### Archivo: `blockchain/fork_sealant.py`, `blockchain/ipc_red.py`
### Subnúcleos: 7 · Líneas: ~350

| Componente | Función |
|------------|---------|
| ForkSealant | Prevención de forks con 7 nodos |
| NodeReputationManager | Reputación con decay temporal (influencia máx 0.5) |
| CrossChainTracker | IPC real via TCP + heartbeat + HMAC autenticación |
| ReconsensusAgent | Voto ponderado con timeout por nodo (3s) |
| NodeChallenge | Rate limiting (5/min) + backoff exponencial |
| IPC Red | Comunicación entre nodos con mTLS |

---

## 🎯 NÚCLEO 5: HONEYPOT COGNITIVO
### Archivo: `honeypot/__init__.py`
### Subnúcleos: 5 · Líneas: ~370

| Componente | Función |
|------------|---------|
| BehaviorCollector | Escucha en puerto 2222 + 6 señuelos |
| HoneypotSession | Rastreo de sesión con fingerprinting de herramientas |
| PatternInverter | **Clasificación híbrida (reglas + World Model ML)** |
| ResponseShaper | 30+ comandos simulados, 7 usuarios falsos, login realista |
| **Protecciones** | Rate limiting (3/min/IP) + TCP_NODELAY + timing realista |

### Detección de Ataques (11 tipos)
`brute-force` `dictionary` `scanner` `exploit` `sqli` `xss` `fuzzing` `rfi` `lfi` `cmd_inject` `desconocido`

---

## 🌡️ NÚCLEO 6: ENTROPÍA
### Archivo: `utils/entropy_engine.py`
### Subnúcleos: 4 · Líneas: ~200

| Subnúcleo | Función |
|-----------|---------|
| EntropyImpactEstimator | Baseline adaptativo cada hora + historial 500 muestras |
| EntropyShield | DNS tunneling checker + RAM noise + IO traffic |
| Ledger | Registro de todos los eventos de entropía con HMAC |
| Circuit Breaker | Desactiva shield si hay demasiados falsos positivos |

---

## 🧠 NÚCLEO 7: CORTEX DE CONFINAMIENTO
### Archivo: `core/cortex.py`
### Subnúcleos: 4 · Líneas: ~180

- Descongelación gradual en 3 fases (umbrales dinámicos)
- HMAC en toda evidencia de descongelación
- Límite de 1000 evidencias en historial

---

## ☮️ NÚCLEO 8: PROTOCOLO DE PAZ
### Archivo: `core/protocolo_paz.py`
### Subnúcleos: 3 · Líneas: ~150

- Nonce anti-replay + límite 1000
- IdentidadAgente basada en HMAC-SHA256
- Timeout de acuerdos (10s)

---

## 📀 NÚCLEO 9: MEMORIA EPISÓDICA
### Archivo: `core/memoria_episodica.py`
### Subnúcleos: 3 · Líneas: ~130

- Watermark para detectar recuerdos inyectados
- Límite 1000 recuerdos en historial
- HMAC en toda implantación

---

## 🌍 GEONOISE TRACKER
### Archivo: `defense/geonoise.py`
### Líneas: ~170

- **Escaneo WiFi real** vía `netsh wlan show networks mode=bssid`
- **Geocodificación** con OSM Nominatim (vía geopy)
- Jitter anti-fingerprint (15% + determinismo por ventana)
- HMAC en todos los logs de geolocalización
- Fallback a hash(SSID + timestamp) sin WiFi

---

## 🦀 MÓDULO RUST NATIVO
### Archivo: `tqsc-native/` (crate completo)
### Versión: v0.1.0 · Rust 1.97.0

| Función | Syscall Nativa | Fallback Python |
|---------|---------------|-----------------|
| enum_processes() | CreateToolhelp32Snapshot | psutil |
| cache_disrupt() | VirtualAlloc + VirtualFree | ctypes |
| pid_signature() | ReadProcessMemory | psutil + ctypes |

Bridge: `native_bridge.py` con detección automática

---

## 📊 WORLD MODEL ML
### Archivo: `ml/dataset.py`, `ml/train.py`, `ml/inference.py`
### Modelo: ~1.1MB · 68 features · 13 cabezas sklearn

| Cabeza | Predice | Score |
|--------|---------|-------|
| pi_tipo | Tipo de ataque (11 clases) | >0.90 |
| pi_severidad | Severidad (regresión) | MSE 0.45 |
| pi_accion | Acción a tomar (4 clases) | >0.90 |
| cl_loop | ¿Loop degenerativo? | >0.90 |
| cx_congelar | ¿Congelar núcleo? | >0.90 |
| bc_fork | ¿Fork blockchain? | >0.90 |
| cd_necesita | ¿Disrupción caché? | >0.90 |
| en_anomalia | ¿Anomalía entropía? | >0.90 |
| hm_anomalia | ¿Anomalía térmica? | >0.90 |
| ij_aceptable | ¿Acción ética? | >0.90 |
| me_implantacion | ¿Implantar recuerdo? | >0.90 |
| oc_shellcode | ¿Shellcode? | >0.90 |
| ps_reflectivo | ¿Proceso reflectivo? | >0.90 |

Integración en vivo en PatternInverter (clasificación híbrida reglas + ML)

---

## 🖥️ HUD WEB (SOC COMMAND CENTER)
### Archivo: `hud/hud_display.py`
### Puerto: 9090 · Uso: `python run.py --hud`

| Componente | Descripción |
|------------|-------------|
| Severidad | CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL |
| Núcleos | 9 tarjetas con estado en tiempo real |
| Eventos | Timeline: hora | núcleo | ataque | resultado |
| API REST | `/api` devuelve JSON con eventos + métricas + núcleos |
| Auto-refresh | Cada 2 segundos |

---

## 🐳 DOCKER
### Archivo: `Dockerfile`, `docker-compose.yml`

| Servicio | Red | Puertos | mTLS |
|----------|-----|---------|------|
| tqsc-init-certs | — | — | Genera CA |
| tqsc-supervisor | internal | — | ✅ |
| tqsc-ia | internal | — | ✅ |
| tqsc-blockchain | internal | — | ✅ |
| tqsc-defense | internal | /proc:ro | ✅ |
| tqsc-quantum | internal | — | ✅ |
| tqsc-entropy | internal | — | ✅ |
| tqsc-cortex | internal | — | ✅ |
| tqsc-memoria | internal | — | ✅ |
| tqsc-paz | internal | — | ✅ |
| tqsc-honeypot | internal + exposed | 2222, 8080 | ✅ |

Red `tqsc_internal`: bridge aislado (internal: true)

---

## ✅ CI/CD
### Archivo: `.github/workflows/ci.yml`

- Push/PR: Python 3.11, compile, lint, tests, boot check
- Rust build: dtolnay/rust-toolchain + cargo build --release

---

## 📈 MÉTRICAS DEL SISTEMA

| Métrica | Valor |
|---------|-------|
| Núcleos | 9 |
| Subnúcleos | 54+ |
| Líneas de código | ~15,000 |
| Suites de test | 12 |
| Tests individuales | ~80 |
| Bugs corregidos (pentest) | 7 + 1 crítico |
| Ataques soportados (pentest) | 49 (6 niveles) |
| Conexiones máximas | 4,699 conns/s |
| Crashes en pentest | 0 |
| Rate limit efectividad | 99.97% |
| Rust funciones | 3 (syscall, cache, pid) |
| ML cabezas | 13 |
| ML features | 68 |
| ML accuracy | >90% (12/13 cabezas) |
| Servicios Docker | 11 |
| Redes Docker | 2 (1 aislada) |

---

## 🔧 ARCHIVOS CLAVE

| Archivo | Propósito |
|---------|-----------|
| `run.py` | Entry point |
| `tqsc/main.py` | Orquestador de núcleos |
| `tqsc/supervisor.py` | Watchdog multiproceso |
| `tqsc/native_bridge.py` | Puente Rust↔Python |
| `tqsc/supervised_main.py` | Modo supervisado Docker |
| `tqsc/core/octarcq.py` | IA OctaRCQ-X8 |
| `tqsc/defense/__init__.py` | Defensa física |
| `tqsc/defense/geonoise.py` | GeoNoise WiFi+OSM |
| `tqsc/defense/syscall_monitor.py` | Syscall Rust |
| `tqsc/classic_crypto/__init__.py` | AES + Ed25519 + HKDF |
| `tqsc/blockchain/fork_sealant.py` | Blockchain IPC |
| `tqsc/honeypot/__init__.py` | Honeypot cognitivo |
| `tqsc/ia/__init__.py` | IA judicial + cognitive loop |
| `tqsc/core/cortex.py` | Cortex descongelación |
| `tqsc/core/protocolo_paz.py` | Protocolo de Paz |
| `tqsc/core/memoria_episodica.py` | Memoria episódica |
| `tqsc/utils/entropy_engine.py` | Entropía + DNS shield |
| `tqsc/utils/secure_storage.py` | AES-256-GCM en reposo |
| `tqsc/utils/boot_integrity.py` | Verificación arranque |
| `tqsc/utils/tls.py` | mTLS local |
| `tqsc/utils/event_bus.py` | Bus de eventos HUD |
| `tqsc/hud/hud_display.py` | HUD Web SOC |
| `tqsc/ml/inference.py` | World Model inference |
| `tqsc/ml/dataset.py` | Dataset generator |
| `tqsc/ml/train.py` | Model trainer |
| `tqsc-native/src/lib.rs` | Rust FFI |
| `tests/test_*.py` | 12 suites de test |
| `Dockerfile` | Build imagen |
| `docker-compose.yml` | 11 servicios + mTLS |
