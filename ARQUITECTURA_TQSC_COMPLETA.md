# 🏗️ ARQUITECTURA TQSC v1.0 — DOCUMENTO COMPLETO
## BlockDefender Titan Quantum Shield Core
### 6 Núcleos · 68+ Subnúcleos · 2,200+ Líneas · 43 Tests

---

## 📐 DIAGRAMA DE ARQUITECTURA

```
                            ┌─────────────────────────────┐
                            │       ORQUESTADOR TQSC       │
                            │         main.py + run.py     │
                            │   Inicia, coordina, monitorea │
                            └──────────┬──────────────────┘
                                       │
            ┌──────────────────────────┼──────────────────────────┐
            │                          │                          │
    ┌───────┴───────┐         ┌───────┴───────┐         ┌───────┴───────┐
    │  NÚCLEO IA     │         │   DEFENSA      │         │   QUANTUM     │
    │  OctaRCQ-X8    │         │   FÍSICA       │         │   Validación  │
    │  18 subnúcleos │         │   10 subnúcleos │         │   6 subnúcleos│
    └───────┬───────┘         └───────┬───────┘         └───────┬───────┘
            │                          │                          │
    ┌───────┴───────┐         ┌───────┴───────┐         ┌───────┴───────┐
    │  BLOCKCHAIN   │         │   HONEYPOT    │         │   ENTROPÍA   │
    │  ForkSealant  │         │   Cognitivo   │         │  NoiseEngine  │
    │  5 subnúcleos │         │   4 subnúcleos │         │  3 subnúcleos │
    └───────────────┘         └───────────────┘         └───────────────┘
    
    ┌───────────────────────────────────────────────────────────────────┐
    │                  MÓDULOS FUTURISTAS (v10.0)                       │
    │  Cortex de Confinamiento · Protocolo de Paz · Memoria Episódica   │
    └───────────────────────────────────────────────────────────────────┘
```

---

## 🧠 NÚCLEO 1: IA AUTOEVOLUTIVA (OctaRCQ-X8)
### Archivo: `core/octarcq.py` + `core/octa_nucleo.py` + `ia/__init__.py`
### Subnúcleos: 18 · Líneas: ~400

### Descripción General
Cerebro del sistema. Procesa eventos a través de una cadena cognitiva de 4
filtros de seguridad, distribuye a 8 octantes de procesamiento paralelo,
y mantiene sombras para failover inmediato.

### Pipeline de Procesamiento (4 filtros en orden aleatorio)

```
Evento entrante
    │
    ├─ ❶ PatternGate
    │   Filtra patrones de entrada adversarial (XSS, inyección, etc.)
    │   Palabras bloqueadas: "bloqueado", "恶意", "<script"
    │   └── Bloqueado → GhostMemory (evacuado, no perdido)
    │
    ├─ ❷ PreImpactSynthesizer
    │   Anticipa amenazas antes de procesar
    │   Señales de riesgo: drop, delete, shutdown, fork, exec
    │   Umbral: 0.15 (1/5 señales activa evacuación)
    │   └── Amenaza → GhostMemory
    │
    ├─ ❸ IA Judicial Interna
    │   Módulo moral y legal. Acciones destructivas requieren aprobación
    │   Acciones bloqueadas: delete_system, shutdown_all, escalate_privilege
    │   └── Ilegal → GhostMemory
    │
    ├─ ❹ QuantumValidator
    │   Verifica estructura lógica y coherencia del evento
    │   Confianza mínima: 85% (VeracitySynthesizer)
    │   └── Inválido → GhostMemory
    │
    └── ✅ Aceptado → ContextWeaver → 8 OctaNucleos
```

### Subnúcleos Detallados

| # | Subnúcleo | Archivo | Función |
|:-:|:----------|:--------|:--------|
| 1 | **OctaNucleo (x8)** | `core/octa_nucleo.py` | Unidad cognitiva base. Buffer de entrada, ADN hash (trazabilidad evolutiva), shadow clone para failover, estado (activo/aislado/latente). Cada octante tiene 2 sub-octantes hijos. |
| 2 | **PatternGate** | `core/octa_nucleo.py` | Filtro de entrada. Bloquea patrones adversariales conocidos. |
| 3 | **PreImpactSynthesizer** | `core/octa_nucleo.py` | Anticipa amenazas. Umbral configurable de señales de riesgo. |
| 4 | **GhostMemoryZone** | `core/octa_nucleo.py` | Memoria para eventos evacuados (no procesados pero recuperables). Máx 100 eventos. |
| 5 | **ContextWeaver** | `ia/__init__.py` | Fusiona patrón con contexto de origen. |
| 6 | **PredictiveReinforcer** | `ia/__init__.py` | Refuerza patrones en núcleos según contenido. |
| 7 | **ModelTrainer** | `ia/__init__.py` | Entrena modelos predictivos sobre patrones recibidos. |
| 8 | **CognitiveLoopDetector** | `ia/__init__.py` | Detecta ciclos degenerativos (mismas respuestas, sin mejora). Aísla el núcleo si detecta ≤2 patrones únicos en últimos 10. |
| 9 | **MetaCoreAdjuster** | `ia/__init__.py` | Reajusta hiperparámetros si la IA se estanca. Reactiva núcleos aislados si el historial es suficiente. |
| 10 | **PatternTransfuser** | `ia/__init__.py` | Transfiere patrones entre núcleos con validación anti-envenenamiento. Bloquea transferencias desde núcleos aislados o con patrones maliciosos. |
| 11 | **ShadowCloneManager** | `ia/__init__.py` | Gestiona clones shadow para failover inmediato. Si un núcleo principal se corrompe, su shadow toma el control. |
| 12 | **IAJudicialInterna** | `ia/__init__.py` | Módulo moral/legal. Toda acción destructiva pasa por aquí. |
| 13 | **EthicalConsensusGate** | `ia/__init__.py` | Requiere consenso entre múltiples decisiones (≥2/3). |
| 14 | **MutationLogger** | `ia/__init__.py` | Registro completo de cada mutación del ADN del núcleo. |
| 15 | **RCQNeuralShield** | `ia/__init__.py` | Escudo neural por núcleo. Aísla núcleos con comportamiento degenerativo. |
| 16 | **PersistenceEngineQMem** | `core/octarcq.py` | Memoria latente con HMAC. Preserva estado entre reinicios. Verifica integridad al cargar. |
| 17 | **OctaRCQ-X8** | `core/octarcq.py` | Orquestador principal. Integra los 18 subnúcleos. Recibe eventos, aplica filtros en orden aleatorio, distribuye a 8 octantes. |
| 18 | **(Cortex de Confinamiento)** | `core/cortex.py` | 🆕 Supervisor externo. Monitorea ciclos del IA Core. Congela LoRA si detecta auto-envenenamiento recursivo. |

---

## 🛡️ NÚCLEO 2: PROTECCIÓN FÍSICA ANTI-SIDE-CHANNEL
### Archivo: `defense/__init__.py` + `defense/geonoise.py`
### Subnúcleos: 12 · Líneas: ~370

### Descripción General
Bloquea ataques que explotan fugas físicas del hardware: caché, temperatura,
emisiones EM, syscalls, patrones térmicos. Incluye geolocalización por firma EM.

### Subnúcleos Detallados

| # | Subnúcleo | Función |
|:-:|:----------|:--------|
| 1 | **CPUUsageScanner** | Monitorea procesos con uso anómalo de CPU (>80%). Detecta nmap, cryptominers, fork bombs. |
| 2 | **SyscallMonitor** | Intercepta llamadas críticas (NtCreateProcess, VirtualAlloc, WriteProcessMemory). Detecta inyección de DLL, fileless payloads. |
| 3 | **CacheDisruptor** | Inyecta 1MB de ruido (os.urandom) en L1/L2 para romper predicciones side-channel. |
| 4 | **ThermalSensor** | Monitorea temperatura CPU/GPU vía psutil.sensors_temperatures(). Si >80°C con actividad desproporcionada, activa alerta. Graceful en Windows (hasattr). |
| 5 | **ProcessAffinityGuard** | Aísla procesos sospechosos a CPUs específicas para limitar su capacidad de escaneo/interferencia. |
| 6 | **OpcodeInterruptionEngine** | Detecta secuencias de instrucciones sospechosas (NOP sleds, CALLs encadenados, JMP reflejados). |
| 7 | **HeatMapDifferentialShield** | Correlaciona uso lógico (RAM, I/O, CPU) con firma térmica por PID. |
| 8 | **PIDSignatureMatcher** | Compara hash SHA256 del binario en disco vs memoria. Detecta manipulación en caliente. |
| 9 | **InterruptVectorValidator** | (Simulado) Verifica integridad de vectores IRQ e IDT contra rootkits. |
| 10 | **SideChannelInhibitor** | (Simulado) Detecta actividad EM/sonora anómala. Genera interferencia inversa. |
| 11 | **EMSignature** | Firma electromagnética de una conexión (nivel EM, armónicos, modulación en ms). |
| 12 | **GeoNoiseTracker** | Geolocaliza origen por firma EM + latencia + huso horario + idioma + clock drift. Precisión: ±50-800m. Anti-spoofing vía jitter gaussiano. 20 ciudades. Mapa Google Maps. |

---

## 🔬 NÚCLEO 3: VALIDACIÓN CUÁNTICA PREDICTIVA
### Archivo: `quantum/__init__.py`
### Subnúcleos: 5 · Líneas: 106

### Descripción General
Emula un entorno de validación tipo QKD sin hardware cuántico real.
Verifica estructura lógica, asigna veracidad, predice manipulación,
valida claves entrelazadas y audita decisiones.

### Subnúcleos Detallados

| # | Subnúcleo | Función |
|:-:|:----------|:--------|
| 1 | **QuantumValidator** | Verifica estructura lógica del evento. Retorna False si falta timestamp, hash o firma. |
| 2 | **VeracitySynthesizer** | Asigna porcentaje de veracidad (0-1). Penalización progresiva por campos faltantes. Bonus por hash/firma. Umbral por defecto: 85%. |
| 3 | **EntangledKeyValidator** | Verifica que una clave esté entrelazada con su origen. La clave debe ser SHA256(origen + timestamp). |
| 4 | **QuantumAuditLogger** | Registra todas las decisiones con firma digital y persistencia a JSONL. |
| 5 | **QuantumCore** | Orquestador del núcleo cuántico. Procesa evento completo: validar → veracidad → auditar. |

---

## ⛓️ NÚCLEO 4: BLOCKCHAIN MULTICANAL + INTEGRIDAD DISTRIBUIDA
### Archivo: `blockchain/fork_sealant.py`
### Subnúcleos: 7 · Líneas: 229

### Descripción General
Garantiza que los registros del sistema no puedan bifurcarse, falsificarse
o manipularse. Consenso entre nodos testigo con reputación ponderada,
desafíos criptográficos, firmas HMAC.

### Subnúcleos Detallados

| # | Subnúcleo | Función |
|:-:|:----------|:--------|
| 1 | **ForkSealant** | Detecta forks maliciosos en registros distribuidos. Verifica hash contra nodos registrados. Registra evento con firma HMAC. |
| 2 | **CrossChainTracker** | Verifica consistencia entre nodos usando voto ponderado por reputación. Si peso <50%, inicia reconsenso. |
| 3 | **ReconsensusAgent** | Votación distribuida ponderada por reputación. Cada nodo vota con peso = min(score, max_influencia). Log firma HMAC. |
| 4 | **NodeReputationManager** | Sistema de reputación híbrida. Score se actualiza por consistencia de voto (+0.1 consistente, -0.25 inconsistente). Decaimiento temporal (-0.02/5min sin actividad). Techo de influencia por nodo (0.5). Penalización por fallar desafío (-0.4). |
| 5 | **NodeChallenge** | Desafíos criptográficos HMAC-SHA256. Nonce de 16 bytes. Timeout 5s. Respuesta incorrecta → penalización. |
| 6 | **_firmar()** | Firma HMAC-SHA256 de cualquier diccionario. Secreto rotado por sesión. |
| 7 | **_persistir_log()** | Escribe cualquier log con firma HMAC incrustada. |

---

## 🍯 NÚCLEO 5: HONEYPOTS COGNITIVOS
### Archivo: `honeypot/__init__.py`
### Subnúcleos: 5 · Líneas: 154

### Descripción General
Sistema señuelo que atrae, observa, engaña y registra atacantes en
tiempo real. No solo detecta: interactúa activamente para recolectar
inteligencia.

### Subnúcleos Detallados

| # | Subnúcleo | Función |
|:-:|:----------|:--------|
| 1 | **HoneypotSession** | Registro completo de una sesión de atacante: IP, timestamp, comandos, credenciales, tipo de ataque. |
| 2 | **PatternInverter** | Clasifica tipo de ataque por credenciales (brute-force, dictionary, scanner). Genera respuestas falsas (whoami → www-data). |
| 3 | **ResponseShaper** | Recrea entorno de víctima falso con banner "Ubuntu 22.04 LTS". Directorios falsos: /etc, /var/log, /home/admin, /root. |
| 4 | **BehaviorCollector** | Escucha en puerto 2222 TCP. Rate limiting (5 conexiones/min/IP). Máx 50 conexiones simultáneas. Lanza hilos por sesión. LOG de eventos. |
| 5 | **_persistir()** | Guarda sesión a JSON con nombre basado en IP. |

---

## 🔊 NÚCLEO 6: ENTROPY NOISE ENGINE
### Archivo: `utils/entropy_engine.py`
### Subnúcleos: 4 · Líneas: 126

### Descripción General
Antifragilidad digital. Detecta y responde a manipulaciones en los niveles
de entropía del sistema, típicas en cargas evasivas o técnicas stealth.

### Subnúcleos Detallados

| # | Subnúcleo | Función |
|:-:|:----------|:--------|
| 1 | **EntropyImpactEstimator** | Mide entropía del sistema vía os.urandom(4096). 10 muestras. Ratio de bytes únicos / 256. Si desviación >15% vs baseline (0.68), activa alarma. |
| 2 | **EntropyShield** | Activa contramedidas: RAMNoiseInterceptor (procesos con >50MB RSS), IOTrafficNoiseChecker (tráfico de red >10MB). |
| 3 | **EntropyTraceLedger** | Registro forense con firma SHA256. Persistencia a JSONL. |
| 4 | **EntropyNoiseEngine** | Motor completo. Ejecuta ciclo: medir → detectar anomalía → activar shield → registrar. |

---

## 🖥️ MÓDULOS ADICIONALES

### HUD Visual
**Archivo:** `hud/hud_display.py` (67 líneas)

Panel visual estilo sala de mando DEFCON. Muestra en tiempo real:
- Estado de cada núcleo (🟢 activo, 🔴 inactivo)
- Métricas del sistema (versión, sesiones de honeypot)
- Spinner animado

Compatible con Windows (cls) y Linux/Mac (clear).

### Configuración Global
**Archivo:** `config.py` (37 líneas)

Constantes centralizadas:
- `DEFAULT_NODOS` — Hashes de nodos blockchain
- `HPA_TENSION_MAX` — Umbral de tensión semántica (0.45/0.80)
- `OCTA_NUCLEOS` — Número de octantes (8)
- `VERACIDAD_MIN` — Umbral de veracidad cuántica (0.85)
- `ENTROPY_BASELINE` — Baseline de entropía (0.68)
- `HONEYPOT_PUERTO` — Puerto de honeypot (2222)

### Orquestador Principal
**Archivo:** `main.py` (126 líneas) + `run.py` (45 líneas)

`main.py` — Clase TQSC que inicializa los 6 núcleos, los arranca en orden,
captura errores con traceback completo.

`run.py` — Punto de entrada CLI. Soporta:
- `python run.py` → Modo normal (rotación IA Core cada 10s)
- `python run.py --test` → Test rápido (arranca + detiene)
- `python run.py --hud` → Modo visual con HUD

---

## 🆕 MÓDULOS FUTURISTAS (v10.0)

### Cortex de Confinamiento
**Archivo:** `core/cortex.py` (146 líneas)

Supervisor autónomo que monitorea el estado del LoRA/IA Core.
Detecta auto-envenenamiento recursivo midiendo:
- Confianza cayendo entre ciclos
- Hipótesis repetidas sin fuentes nuevas
- Errores aumentando >1.5x
- Confianza proyectada en descenso

Si ≥2 señales se activan durante `max_deg` ciclos consecutivos:
→ Congela el LoRA
→ Persiste evidencia forense
→ LOG crítico
→ Espera descongelación manual

### Protocolo de Paz entre Agentes
**Archivo:** `core/protocolo_paz.py` (134 líneas)

Handshake criptográfico para comunicación entre agentes autónomos:
- `IdentidadAgente`: ID único + secreto HMAC
- `MensajePaz`: Firma HMAC-SHA256 del contenido
- `RegistroAgentes`: Estado de confianza (confiable/sospechoso/aislado)
- `ProtocoloPaz`: Enviar/recibir/verificar mensajes

### Memoria Episódica con Marca de Agua
**Archivo:** `core/memoria_episodica.py` (126 líneas)

Cada recuerdo lleva marca de agua estadística:
- `Recuerdo`: contenido + timestamp + watermark SHA256(contenido:timestamp:key)[:8]
- `MemoriaEpisodica`: almacén con verificación
- `DetectorDeImplantacion`: analiza patrones (watermarks duplicados, ráfagas de timestamps)

Probabilidad de falsificación: 1/4,294,967,296

---

## 🔬 SUITE DE TESTS (43 tests)

| Archivo | Tests | ¿Qué prueba? |
|:--------|:-----:|:-------------|
| `test_entropy.py` | 3 | Estimador de entropía, ledger con firma, ciclo completo |
| `test_fork_sealant.py` | 5 | Verificación de hashes, consenso por reputación, reconsenso |
| `test_geonoise.py` | 5 | Firma multidimensional, precisión ciudad, determinismo, HTML, persistencia |
| `test_ia_core.py` | 5 | OctaNucleo, aislamiento, shadow clone, PatternGate, GhostMemory |
| `test_ia_core_octarcq.py` | 5 | OctaRCQ completo, filtros, rotación, shadow clones, ghost memory |
| `test_reputacion.py` | 6 | Reputación inicial, penalización, recuperación, desafío exitoso, timeout, respuesta incorrecta |
| `test_v10_futuro.py` | 8 | Cortex (normal, congelar, descongelar), ProtocoloPaz (handshake, falso), MemoriaEp (almacenar, implantación, detector) |

---

## 📊 ESTADÍSTICAS COMPLETAS

```
Métrica                          Valor
──────────────────────────────────────────────
Total líneas de código           2,200+
Archivos Python                   17
Clases                            47
Funciones                         116
Tests                             43 en 7 suites
Núcleos                          6
Subnúcleos                       68+
Módulos futuristas               3
Páginas de documentación         6
Simulaciones de ataque           2 (47min + 72h)
Bugs corregidos                  19
Dependencias externas            1 (psutil)
```

---

## 📁 ESTRUCTURA COMPLETA DE ARCHIVOS

```
Proyecto TQSC/v1.0/
│
├── run.py                          ← CLI entry point (--test, --hud)
├── requirements.txt                ← psutil
│
├── THREAT_INTEL_2025_2026.md       ← Amenazas actuales
├── THREAT_INTEL_2031_FUTURISTA.md  ← Amenazas futuristas
├── SIMULACION_ATAQUE_TQSC.md       ← Simulación 47min
├── SIMULACION_ESTRES_3DIAS.md      ← Simulación 72h
│
├── tqsc/
│   ├── __init__.py
│   ├── config.py                   ← Constantes globales
│   ├── main.py                     ← Orquestador TQSC
│   │
│   ├── core/                       ← NÚCLEO: IA Autoevolutiva
│   │   ├── __init__.py
│   │   ├── octa_nucleo.py          ← 4 subnúcleos base
│   │   ├── octarcq.py              ← Orquestador 18 subnúcleos
│   │   ├── cortex.py               ← 🆕 Cortex de Confinamiento
│   │   ├── protocolo_paz.py        ← 🆕 Protocolo entre agentes
│   │   └── memoria_episodica.py    ← 🆕 Memoria con marca de agua
│   │
│   ├── ia/                         ← NÚCLEO: Módulos IA (10 subnúcleos)
│   │   └── __init__.py
│   │
│   ├── blockchain/                 ← NÚCLEO: Integridad Distribuida
│   │   ├── __init__.py
│   │   └── fork_sealant.py         ← 7 subnúcleos
│   │
│   ├── quantum/                    ← NÚCLEO: Validación Cuántica
│   │   ├── __init__.py             ← 5 subnúcleos
│   │
│   ├── defense/                    ← NÚCLEO: Protección Física
│   │   ├── __init__.py             ← 10 subnúcleos
│   │   └── geonoise.py             ← 2 subnúcleos + 20 ciudades
│   │
│   ├── honeypot/                   ← NÚCLEO: Honeypots Cognitivos
│   │   ├── __init__.py             ← 5 subnúcleos
│   │
│   ├── hud/                        ← MÓDULO: Interfaz Visual
│   │   ├── __init__.py
│   │   └── hud_display.py
│   │
│   └── utils/                      ← MÓDULO: Utilidades
│       ├── __init__.py
│       └── entropy_engine.py       ← 4 subnúcleos
│
└── tests/                          ← 43 TESTS
    ├── test_entropy.py
    ├── test_fork_sealant.py
    ├── test_geonoise.py
    ├── test_ia_core.py
    ├── test_ia_core_octarcq.py
    ├── test_reputacion.py
    └── test_v10_futuro.py
```
