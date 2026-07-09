# 🗺️ TQSC v2.0 — HOJA DE RUTA PARA PRODUCCIÓN REAL
## 7 pilares para pasar de prototipo a infraestructura crítica
### Basado en autocrítica · Sin marketing · Sin complecer

---

## 📊 PRIORIZACIÓN POR IMPACTO/ESFUERZO

| # | Pilar | Esfuerzo | Impacto | Prioridad |
|:-:|:------|:--------:|:-------:|:---------:|
| 1 | **Aislar núcleos como procesos independientes** | 2 semanas | 🔴 Crítico | **🔥 1** |
| 2 | **Firma digital al arranque** (boot integrity) | 3 días | 🔴 Crítico | **🔥 2** |
| 3 | **Cifrado AES-256-GCM en reposo** | 1 semana | 🔴 Crítico | **🔥 3** |
| 4 | **Renombrar "quantum" → "criptografía clásica"** | 5 min | 🟡 Medio | **✅ Inmediato** |
| 5 | **Núcleos críticos en Rust** | 3-4 meses | 🔴 Crítico | **⏳ Largo plazo** |
| 6 | **GeoNoiseTracker: funcional o eliminado** | Decisión | 🟡 Medio | **⏳ Pendiente** |
| 7 | **Tests contra malware real** | 1 mes | 🟡 Medio | **⏳ Largo plazo** |

---

## 🔥 PILAR 1: AISLAR CADA NÚCLEO COMO PROCESO INDEPENDIENTE
### Esfuerzo: 2 semanas · Prioridad: 🔴 MÁXIMA

### Problema
Hoy TQSC corre en un solo proceso Python. Si `main.py` muere, mueren los 9 núcleos.

### Solución
Cada núcleo → proceso independiente con comunicación via IPC (ZeroMQ o sockets UNIX).

### Arquitectura

```
┌──────────────────────────────────────────────┐
│              WATCHDOG (supervisor.py)          │
│  Monitorea: heartbeat, uptime, estado         │
│  Acción: reiniciar núcleo caído, alertar      │
├──────────────────────────────────────────────┤
│                                                │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │ IA Core  │  │ Defense  │  │ Quantum  │    │
│  │ (proc 1) │  │ (proc 2) │  │ (proc 3) │    │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘    │
│       │              │              │          │
│  ┌────┴─────┐  ┌────┴─────┐  ┌────┴─────┐    │
│  │Blockchain│  │ Honeypot │  │ Entropy  │    │
│  │ (proc 4) │  │ (proc 5) │  │ (proc 6) │    │
│  └──────────┘  └──────────┘  └──────────┘    │
│                                                │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │ Cortex   │  │Paz       │  │ Memoria  │    │
│  │ (proc 7) │  │ (proc 8) │  │ (proc 9) │    │
│  └──────────┘  └──────────┘  └──────────┘    │
└──────────────────────────────────────────────┘
```

### Plan de implementación

| Día | Tarea | Entregable |
|:---:|:------|:-----------|
| 1-2 | Crear `supervisor.py` con watchdog + heartbeat | Watchdog funcional |
| 3-4 | Convertir IA Core en proceso independiente (ZeroMQ) | IA Core aislado |
| 5-6 | Convertir Defense + Quantum en procesos independientes | 3 núcleos aislados |
| 7-8 | Convertir Blockchain + Honeypot + Entropy | 6 núcleos aislados |
| 9-10 | Convertir Cortex + Paz + Memoria | 9 núcleos aislados |
| 11-12 | Tests de caída: matar núcleo aleatorio → watchdog lo reinicia | Resiliencia probada |
| 13-14 | Documentación + integración final | **MVP v2.0** |

### Código necesario (estimado)
```
tqsc/
├── supervisor.py          ← NUEVO: watchdog principal (300 líneas)
├── ipc/                   ← NUEVO: comunicación entre procesos
│   ├── __init__.py
│   ├── messages.py        ← Protocolo de mensajes (100 líneas)
│   └── transport.py       ← ZeroMQ o sockets (150 líneas)
├── core/ → core_daemon.py ← NUEVO: wrapper para cada núcleo (50 líneas c/u)
└── tests/
    └── test_supervisor.py ← Tests de caída/resiliencia (200 líneas)
```

---

## 🔥 PILAR 2: FIRMA DIGITAL AL ARRANQUE (BOOT INTEGRITY)
### Esfuerzo: 3 días · Prioridad: 🔴 MÁXIMA

### Problema
Cualquiera con acceso al disco puede modificar `main.py`, `fork_sealant.py`, etc.
TQSC arranca sin verificar que sus propios archivos no hayan sido alterados.

### Solución
1. Generar una clave HMAC maestra al primer arranque
2. Calcular hash SHA256 de cada `.py` del sistema
3. Al arrancar, verificar cada hash contra la firma almacenada
4. Si algún archivo no coincide → TQSC se niega a arrancar

### Plan

| Día | Tarea |
|:---:|:------|
| 1 | `boot_integrity.py`: generación de clave + fingerprinting inicial |
| 2 | Verificación al arranque + alerta si hay modificación |
| 3 | Tests + documentación |

---

## 🔥 PILAR 3: CIFRADO AES-256-GCM EN REPOSO
### Esfuerzo: 1 semana · Prioridad: 🔴 MÁXIMA

### Problema
Logs, evidencias, ledgers, blockchain, reputación — todo es JSON plano.
Si un atacante accede al disco, tiene toda la información forense.

### Solución
Cifrar cada archivo de log con AES-256-GCM antes de escribirlo.

### Archivos a cifrar
```
data/
├── fork_event.json           ← fork_sealant
├── node_compromised.json     ← reputación
├── resolucion_reconsensus.json ← blockchain
├── cortex_evidencia.json     ← cortex
├── qmem_state.json           ← memoria persistente
├── quantum_audit.jsonl       ← auditoría cuántica
├── syscall_alertas.jsonl     ← syscall monitor
├── entropy_ledger.jsonl      ← entropía
├── mutualog.json             ← mutaciones IA
├── reputacion.json           ← blockchain
├── auditoria_judicial.json   ← IA judicial
└── honeypot_*.json           ← honeypots
```

### Clase necesaria
```python
class CifradorAES:
    def cifrar(self, datos: dict, ruta: Path) -> bytes
    def descifrar(self, ruta: Path) -> dict
    def rotar_clave(self)
```

---

## ✅ PILAR 4: RENOMBRAR "QUANTUM" → "CRIPTOGRAFÍA CLÁSICA"
### Esfuerzo: 5 minutos · Prioridad: 🟡 INMEDIATA

### Acción
Renombrar carpeta `quantum/` → `classic_crypto/`. Renombrar `QuantumCore` → `ClassicCryptoCore`. Renombrar `QuantumValidator` → `CryptoValidator`. Renombrar `QuantumAuditLogger` → `CryptoAuditLogger`. Actualizar imports. Ejecutar tests. Fin.

---

## ⏳ PILAR 5: NÚCLEOS CRÍTICOS EN RUST
### Esfuerzo: 3-4 meses · Prioridad: 🔴 LARGO PLAZO

### Módulos a reescribir

| Módulo | Lugar actual | Lugar nuevo | Prioridad |
|:-------|:------------|:------------|:---------:|
| SyscallMonitor | `defense/syscall_monitor.py` | `native/syscall/` | 🔴 Alta |
| CacheDisruptor | `defense/__init__.py` | `native/cache/` | 🔴 Alta |
| PIDSignatureMatcher | `defense/__init__.py` | `native/pid_sig/` | 🔴 Alta |

### Interfaz Python ↔ Rust
```python
import tqsc_native
tqsc_native.syscall_monitor()  # retorna dict vía PyO3
tqsc_native.cache_disrupt()    # invalidación real de L1/L2
tqsc_native.pid_verify(pid)    # hash en memoria real
```

### Stack
- **PyO3** para bindings Python-Rust
- **Maturin** para build
- Cross-compilación para Windows/Linux

### Esfuerzo estimado
```
Módulo        Líneas Rust  Líneas Python  Esfuerzo
─────────────────────────────────────────────────────
SyscallMonitor  ~800         ~50            6 semanas
CacheDisruptor  ~400         ~30            3 semanas
PIDSignature    ~500         ~30            4 semanas
─────────────────────────────────────────────────────
Total          ~1,700       ~110           13 semanas (~3 meses)
```

---

## ⏳ PILAR 6: GEONOISETRACKER — DECISIÓN
### Esfuerzo: Decisión tuya

### Opciones

| Opción | Impacto | Esfuerzo |
|:-------|:-------:|:--------:|
| **A) Eliminarlo** | Pierdes geolocalización, ganas honestidad | 1 hora |
| **B) Hacerlo funcional** (SDR + datos reales) | Geolocalización real, pero requiere hardware | 2-3 meses + $500 HW |
| **C) Mantenerlo como "simulación"** (documentar que es PoC) | Utilidad limitada pero no es mentira | Documentar |

**Mi recomendación:** Opción C por ahora. Opción B si consigues un SDR (RTL-SDR ~$30).

---

## ⏳ PILAR 7: TESTS CONTRA MALWARE REAL
### Esfuerzo: 1 mes · Prioridad: 🟡

### Qué probar
- **Metasploit**: `exploit/multi/handler`, `auxiliary/scanner/ssh/ssh_login`
- **Cobalt Strike**: beacon HTTP/DNS, payloads
- **Ransomware** real: descifrar hashes, detectar patrones
- **Nmap**: detección por SyscallMonitor
- **Hydra/Medusa**: detección por honeypot
- **SQLMap**: detección por PatternInverter

### Cómo
1. Montar VM víctima con TQSC
2. VM atacante con Kali Linux + herramientas reales
3. Ejecutar ataques reales
4. Verificar que TQSC detecta, bloquea, registra
5. Ajustar lo que falle

---

## 📊 RESUMEN DE ESFUERZO

| Pilar | Prioridad | Esfuerzo | Depende de |
|:------|:---------:|:--------:|:-----------|
| 1. Aislar núcleos | 🔴 Crítica | 2 semanas | — |
| 2. Boot integrity | 🔴 Crítica | 3 días | — |
| 3. Cifrado en reposo | 🔴 Crítica | 1 semana | — |
| 4. Renombrar quantum | 🟡 Inmediata | 5 minutos | — |
| 5. Rust para críticos | 🔴 Largo plazo | 3-4 meses | Pilar 1 |
| 6. GeoNoise decisión | 🟡 Decisión | — | Tu decisión |
| 7. Tests reales | 🟡 Largo plazo | 1 mes | Pilares 1-2 |

**Total estimado (sin Rust): ~3-4 semanas**  
**Total estimado (con Rust): ~4-5 meses**

---

## 🏁 PRIMEROS PASOS (HOY)

1. ✅ **Renombrar "quantum" → "classic_crypto"** (5 min)
2. 🔲 **Crear boot_integrity.py** (3 días)
3. 🔲 **Crear supervisor.py con watchdog** (2 semanas)
4. 🔲 **Crear cifrador AES-256-GCM** (1 semana)
5. 🔲 **Decidir GeoNoise** (1 hora)
6. 🔲 **Rust** (meses)
7. 🔲 **Tests reales** (mes)

¿Arrancamos por el 1 (renombrar quantum) y el 2 (boot integrity) que son los más rápidos y de mayor impacto inmediato?
