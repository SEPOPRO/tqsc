# 🗺️ HOJA DE RUTA TQSC — PRODUCCIÓN REAL
## BlockDefender Titan Quantum Shield Core v1.0 → v10.0
### Priorización por impacto crítico · Código sustancial, sin stubs

---

> [!IMPORTANT]
> **Nota de honestidad (2026-07-28):** Los estados marcados como 🟢 en esta hoja de ruta indican que la ESTRUCTURA del código existe y funciona, no que la implementación sea equivalente a un producto comercial. Ver LIMITACIONES_ML.md para limitaciones del ML. Los nombres de clases como 'ModelTrainer', 'RCQNeuralShield', 'QuantumValidator' son metafóricos — las implementaciones reales usan heurísticas simples basadas en diccionarios y contadores.

## 📊 LEYENDA

| Símbolo | Significado |
|:-------:|:------------|
| 🟢 **Listo** | Implementación sustancial, testeada, lista para integrar |
| 🟡 **En desarrollo** | Funciona pero requiere expansión para producción |
| 🔴 **Stub** | Existe la clase/función pero la lógica es placeholder |
| ⚪ **No iniciado** | No hay código |

---

## 🧠 NÚCLEO 1: IA AUTOEVOLUTIVA (OctaRCQ-X8)
### Archivos: `core/octa_nucleo.py`, `core/octarcq.py`, `ia/__init__.py`
### Prioridad: 🔴 CRÍTICA (es el cerebro del sistema)

### Roadmap

| # | Subnúcleo | Estado | Prioridad | Esfuerzo | Acción Requerida |
|:-:|:----------|:------:|:---------:|:--------:|:-----------------|
| 1 | **OctaNucleo (x8)** | 🟢 Listo | Alta | — | Base sólida. Buffer, ADN hash, shadow clone, estado. OK. |
| 2 | **PatternGate** | 🟢 Listo | Alta | — | Filtro de palabras clave. OK. Expandir lista de bloqueo. |
| 3 | **PreImpactSynthesizer** | 🟢 Listo | Alta | 3h ✅ | Umbral adaptativo por historial de FP, 5 categorías de señales con pesos, score por severidad. |
| 4 | **GhostMemoryZone** | 🟢 Listo | Media | — | Buffer de 100 eventos. OK para ahora. |
| 5 | **ContextWeaver** | 🟢 Listo | Media | 2h ✅ | Añade timestamp, confianza de origen, tipo de evento, huella MD5. |
| 6 | **PredictiveReinforcer** | 🟢 Listo | Baja | 4h ✅ | Refuerzo por frecuencia de patrón, no aleatorio. |
| 7 | **ModelTrainer** | 🟢 Listo | Baja | 4h ✅ | Contador de patrones únicos vistos, mutación informada por cardinalidad. |
| 8 | **CognitiveLoopDetector** | 🟢 Listo | Alta | — | Detecta ≤2 patrones únicos en últimos 10. OK. |
| 9 | **MetaCoreAdjuster** | 🔴 Stub | Media | 3h | Reactiva núcleos aislados. Debe reajustar hiperparámetros reales. |
| 10 | **PatternTransfuser** | 🟢 Listo | Alta | — | Validación anti-envenenamiento. OK desde última sesión. |
| 11 | **ShadowCloneManager** | 🟢 Listo | Media | — | Clonación y failover. OK. |
| 12 | **IAJudicialInterna** | 🟢 Listo | 🔴 **Crítica** | **8h ✅** | Lista dinámica por categorías, severidad 1-10, umbral 5, historial completo, exportación JSON, reglas dinámicas en runtime. |
| 13 | **EthicalConsensusGate** | 🟢 Listo | Alta | 4h ✅ | Voto ponderado con pesos por decisión, umbral 50%, modo simple 2/3. |
| 14 | **MutationLogger** | 🟢 Listo | Media | 2h ✅ | Exportación JSON, tasa de anomalía por frecuencia de mutaciones, historial 1000. |
| 15 | **RCQNeuralShield** | 🔴 Stub | Alta | 4h | Misma lógica que CognitiveLoopDetector. Debe tener su propio umbral y algoritmo de detección. |
| 16 | **PersistenceEngineQMem** | 🟢 Listo | Alta | — | HMAC en guardado/carga. OK desde última sesión. |
| 17 | **OctaRCQ-X8** | 🟢 Listo | Alta | — | Orquestador con filtros aleatorios. OK. |
| 18 | **CortexDeConfinamiento** | 🟢 Listo | Alta | — | Congelamiento por detección degenerativa. OK. Pendiente: descongelación gradual. |

### Acciones Inmediatas (Núcleo 1)
```
1. IAJudicialInterna → 8h (más crítico)
2. EthicalConsensusGate → 4h
3. RCQNeuralShield → 4h
4. CognitiveLoopDetector + MetaCoreAdjuster → 3h
```

---

## 🛡️ NÚCLEO 2: PROTECCIÓN FÍSICA
### Archivos: `defense/__init__.py`, `defense/geonoise.py`
### Prioridad: 🔴 CRÍTICA (defensa en tiempo real)

### Roadmap

| # | Subnúcleo | Estado | Prioridad | Esfuerzo | Acción Requerida |
|:-:|:----------|:------:|:---------:|:--------:|:-----------------|
| 1 | **CPUUsageScanner** | 🟢 Listo | Alta | 3h ✅ | Logging estructurado, umbral configurable (80%), ventana de 60s, alerta por acumulación (>5 procesos). |
| 2 | **SyscallMonitor** | 🟢 Listo | 🔴 **Crítica** | **12h ✅** | ctypes + ntdll real. Monitorea procesos, hilos, combinaciones peligrosas (word→powershell). Alertas en tiempo real. Persistencia JSONL. |
| 3 | **CacheDisruptor** | 🟢 Listo | Alta | 6h ✅ | VirtualAlloc (Windows) + mmap (Linux). 256KB de ruido en L1/L2 con lectura inversa. Fallback a urandom si falla. |
| 4 | **ThermalSensor** | 🟢 Listo | Alta | — | Graceful en Windows, fallback si no hay sensores. OK. |
| 5 | **ProcessAffinityGuard** | 🟢 Listo | Alta | 3h ✅ | Aísla + verifica + rollback. Historial de aislamientos con timestamp. Restauración de afinidad original. |
| 6 | **OpcodeInterruptionEngine** | 🟢 Listo | Media | 4h ✅ | Análisis de opcodes por byte (NOP sled, CALL chain, JMP reflex, INT3 break, shellcode). 5 categorías de patrones. Heurística de shellcode. |
| 7 | **HeatMapDifferentialShield** | 🟢 Listo | Media | 6h ✅ | Ventana deslizante 60s, correlación temp/CPU, detección de diferencial térmico anómalo. |
| 8 | **PIDSignatureMatcher** | 🟢 Listo | Alta | 6h ✅ | Hash disco vs memoria, detección de procesos reflectivos (sin exe), gracef ul en AccessDenied/NoSuchProcess. |
| 9 | **InterruptVectorValidator** | ⚪ No iniciado | Baja | 8h | Requiere acceso Ring 0 (driver kernel). No priorizado. |
| 10 | **SideChannelInhibitor** | ⚪ No iniciado | Baja | 8h | Requiere hardware específico (SDR, micrófonos direccionales). No priorizado. |
| 11 | **EMSignature** | 🟡 En desarrollo | Media | 3h | Firma EM simulada con gauss. Debe: usar datos reales de sensores si disponibles, añadir más dimensiones (fase, amplitud, frecuencia portadora). |
| 12 | **GeoNoiseTracker** | 🟡 En desarrollo | Alta | 8h | 20 ciudades, clock drift, jitter. Para producción: 200+ ciudades, integración con API de Google Maps real, verificación multi-nodo, calibración automática de perfiles EM. |

### Acciones Inmediatas (Núcleo 2)
```
1. SyscallMonitor → 12h (hook user-space real)
2. CacheDisruptor → 6h (CLFLUSH real)
3. PIDSignatureMatcher → 6h (memoria vs disco)
4. GeoNoiseTracker → 8h (expandir)
```

---

## 🔬 NÚCLEO 3: VALIDACIÓN CUÁNTICA
### Archivos: `quantum/__init__.py`
### Prioridad: 🟡 MEDIA (depende de Núcleo 1)

### Roadmap

| # | Subnúcleo | Estado | Prioridad | Esfuerzo | Acción Requerida |
|:-:|:----------|:------:|:---------:|:--------:|:-----------------|
| 1 | **QuantumValidator** | 🟢 Listo | Media | 3h ✅ | Esquema configurable, validación de tipos, logging por campo faltante. |
| 2 | **VeracitySynthesizer** | 🟢 Listo | Media | 4h ✅ | Umbral adaptativo por promedio histórico (95% si prom>0.9), penalización progresiva, historial 100 muestras. |
| 3 | **EntangledKeyValidator** | 🔴 Stub | Baja | 3h | SHA256(origen+timestamp). Debe: usar HMAC con clave rotante, verificar no-repudio, timestamp tolerance. |
| 4 | **QuantumAuditLogger** | 🟢 Listo | Media | — | JSONL con firma. OK. |
| 5 | **QuantumCore** | 🟡 En desarrollo | Media | 2h | Orquestador básico. Debe: pipeline configurable, circuit breaker si tasa de error > umbral. |

### Acciones Inmediatas (Núcleo 3)
```
1. VeracitySynthesizer → 4h (ML ligero)
2. QuantumValidator → 3h (esquema configurable)
```

---

## ⛓️ NÚCLEO 4: BLOCKCHAIN + INTEGRIDAD
### Archivos: `blockchain/fork_sealant.py`
### Prioridad: 🟡 MEDIA (funcional, requiere robustez)

### Roadmap

| # | Subnúcleo | Estado | Prioridad | Esfuerzo | Acción Requerida |
|:-:|:----------|:------:|:---------:|:--------:|:-----------------|
| 1 | **ForkSealant** | 🟢 Listo | Alta | — | Verificación de hashes + HMAC. OK. |
| 2 | **CrossChainTracker** | 🟢 Listo | Alta | **6h ✅** | IPC real via TCP sockets + heartbeat. Red blockchain con fallback a dict local. |
| 3 | **ReconsensusAgent** | 🟢 Listo | Alta | 4h ✅ | Voto ponderado por reputación, timeout por nodo (3s), penalización por timeout, registro en blockchain. |
| 4 | **NodeReputationManager** | 🟢 Listo | Alta | 4h ✅ | Persistencia a disco, score+decaimiento+techo, recuperación post-reinicio. |
| 5 | **NodeChallenge** | 🟢 Listo | Media | 3h ✅ | Rate limiting (5/min), backoff exponencial 2^N (max 16s), máx 3 rondas por nodo. |
| 6 | **_firmar()** | 🟢 Listo | Alta | — | HMAC-SHA256. OK. |
| 7 | **_persistir_log()** | 🟢 Listo | Alta | — | HMAC + JSON. OK. |

### Acciones Inmediatas (Núcleo 4)
```
1. CrossChainTracker → 6h (IPC real entre nodos)
2. ReconsensusAgent → 4h (blockchain no JSON)
3. NodeReputationManager → 4h (persistencia)
```

---

## 🍯 NÚCLEO 5: HONEYPOTS COGNITIVOS
### Archivos: `honeypot/__init__.py`
### Prioridad: 🟢 MEDIA (funcional, varias mejoras)

### Roadmap

| # | Subnúcleo | Estado | Prioridad | Esfuerzo | Acción Requerida |
|:-:|:----------|:------:|:---------:|:--------:|:-----------------|
| 1 | **HoneypotSession** | 🟡 En desarrollo | Media | 2h | Registro IP+comandos. Debe: fingerprinting de herramienta (nmap, metasploit, custom), GeoIP real, duración de sesión. |
| 2 | **PatternInverter** | 🟢 Listo | Alta | **8h ✅** | Clasificación por 7 tipos de ataque, confianza 0.1-1.0, respuestas dinámicas por tipo, sesiones por IP. |
| 3 | **ResponseShaper** | 🟢 Listo | Alta | **8h ✅** | Banner SSH real, respuestas para 11 comandos (whoami, id, ls, cat, ps, netstat), modo Linux/Windows intercambiable. |
| 4 | **BehaviorCollector** | 🟢 Listo | Alta | — | Rate limiting, max conexiones. OK. |
| 5 | **_persistir()** | 🟡 En desarrollo | Media | 1h | JSON por IP. Debe: añadir hash de integridad, rotación de archivos. |

### Acciones Inmediatas (Núcleo 5)
```
1. PatternInverter → 8h (ML + respuestas dinámicas)
2. ResponseShaper → 8h (SSH simulado completo)
```

---

## 🔊 NÚCLEO 6: ENTROPY NOISE ENGINE
### Archivos: `utils/entropy_engine.py`
### Prioridad: 🟢 MEDIA (funcional, expandir)

### Roadmap

| # | Subnúcleo | Estado | Prioridad | Esfuerzo | Acción Requerida |
|:-:|:----------|:------:|:---------:|:--------:|:-----------------|
| 1 | **EntropyImpactEstimator** | 🟢 Listo | Media | 3h ✅ | Baseline adaptativo cada hora, tendencia (creciente/decreciente/estable), historial 500 muestras. |
| 2 | **EntropyShield** | 🟡 En desarrollo | Media | 4h | RAM + IO check. Debe: añadir más contramedidas (disk noise, network noise), priorización por severidad. |
| 3 | **EntropyTraceLedger** | 🟢 Listo | Media | — | JSONL con firma. OK. |
| 4 | **EntropyNoiseEngine** | 🟢 Listo | Media | — | Ciclo completo. OK. |

---

## 🖥️ MÓDULOS ADICIONALES

### HUD Visual
**Archivo:** `hud/hud_display.py` (67 líneas) — 🟡 En desarrollo

| Acción | Esfuerzo | Descripción |
|:-------|:--------:|:------------|
| Web dashboard | **12h** | Reemplazar terminal por web (Flask/FastAPI) con WebSockets |
| Tiempo real | 4h | Streaming de eventos vía SSE |
| Mapa en vivo | 6h | Google Maps con pins animados |
| Historial | 3h | Timeline de eventos con filtros |

### Configuración Global
**Archivo:** `config.py` (37 líneas) — 🟢 Listo

---

## 🆕 MÓDULOS FUTURISTAS (v10.0)

### Cortex de Confinamiento
**Archivo:** `core/cortex.py` (146 líneas) — 🟢 Listo base

| Acción | Esfuerzo | Descripción |
|:-------|:--------:|:------------|
| Descongelación gradual | **6h** | No congelar/descongelar binario. Fase 1: reducir tasa de aprendizaje. Fase 2: pausar inferencia. Fase 3: congelar. Al revés para descongelar. |
| Umbrales dinámicos | 4h | Ajustar max_deg según hora del día, carga del sistema, histórico de falsos positivos. |
| Auto-recovery | 4h | Si después de descongelar el sistema se estabiliza por N ciclos, salir de modo seguro automáticamente. |
| Dashboard | 3h | Métricas exportables: tasa de degeneración, tiempo entre congelamientos, causa raíz. |

### Protocolo de Paz
**Archivo:** `core/protocolo_paz.py` (134 líneas) — 🟢 Listo base

| Acción | Esfuerzo | Descripción |
|:-------|:--------:|:------------|
| Autenticación mutua | 4h | No solo verificar firma del emisor. Ambos lados firman un nonce compartido. |
| Renovación de claves | 3h | Rotación periódica de HMAC_SECRET. |
| Detección de replay | 2h | Protección contra ataques de repetición con nonces de un solo uso. |
| Logging forense | 2h | Registro completo de handshakes exitosos y fallidos. |

### Memoria Episódica
**Archivo:** `core/memoria_episodica.py` (126 líneas) — 🟢 Listo base

| Acción | Esfuerzo | Descripción |
|:-------|:--------:|:------------|
| Persistencia a largo plazo | 4h | SQlite en vez de JSONL para consultas eficientes. |
| Compresión de recuerdos | 4h | Fusión de recuerdos similares (umbral de similitud coseno). |
| Detector de implantación | 4h | No solo watermarks duplicados. Análisis temporal, semántico, y de fuentes. |
| Consultas temporales | 2h | ¿Qué recuerdos tengo de ayer? ¿Cuáles tienen fuente "ataque"? |

---

## 🧪 INFRAESTRUCTURA DE TESTS

### Estado actual: 43 tests en 7 suites — 🟡 Necesita expansión

| Acción | Esfuerzo | Descripción |
|:-------|:--------:|:------------|
| CI/CD | **8h** | GitHub Actions: test automático en cada push, linting, cobertura. |
| Tests de integración | **12h** | No solo unitarios. Probar núcleos funcionando juntos (ej: IA + Cortex). |
| Tests de estrés | **8h** | Automatizar la simulación de 72h como test reproducible. |
| Mocks de hardware | 6h | Simular sensores térmicos, EM, syscalls para tests sin hardware real. |
| Cobertura mínima | 4h | Exigir >80% en núcleos críticos (IA, Blockchain, Defense). |

---

## 📋 PLAN DE IMPLEMENTACIÓN — PRÓXIMAS 10 SESIONES

### Sesión 1 (🔥 PRIORIDAD MÁXIMA)
```
- IAJudicialInterna → lista dinámica de acciones bloqueadas + embeddings
- EthicalConsensusGate → pesos por subnúcleo
```

### Sesión 2
```
- SyscallMonitor → hook user-space real vía ctypes
- CacheDisruptor → CLFLUSH real
```

### Sesión 3
```
- CrossChainTracker → IPC real entre nodos
- NodeReputationManager → persistencia a disco
```

### Sesión 4
```
- PatternInverter → ML para clasificación de ataques
- ResponseShaper → SSH simulado funcional
```

### Sesión 5
```
- GeoNoiseTracker → 200+ ciudades, API Google Maps real
- PIDSignatureMatcher → memoria vs disco + Authenticode
```

### Sesión 6
```
- Descongelación gradual del Cortex
- Umbrales dinámicos
```

### Sesión 7
```
- VeracitySynthesizer → ML ligero
- QuantumValidator → esquema configurable
```

### Sesión 8
```
- HUD Web (Flask + SSE + mapa)
- Dashboard de métricas
```

### Sesión 9
```
- CI/CD (GitHub Actions)
- Tests de integración
- Mocks de hardware
```

### Sesión 10
```
- Revisión general
- Code freeze para v1.0
- Documentación de API
```

---

## 📊 RESUMEN DE ESFUERZO

| Núcleo | Estado | Prioridad | Esfuerzo restante |
|:-------|:------:|:---------:|:-----------------:|
| 1. IA Autoevolutiva | 🟡 7/18 🟢 | 🔴 Crítica | **~25h** |
| 2. Protección Física | 🟡 2/12 🟢 | 🔴 Crítica | **~45h** |
| 3. Validación Cuántica | 🟡 2/5 🟢 | 🟡 Media | **~12h** |
| 4. Blockchain | 🟡 4/7 🟢 | 🟡 Media | **~17h** |
| 5. Honeypots | 🟡 1/5 🟢 | 🟢 Media | **~19h** |
| 6. Entropy Engine | 🟡 2/4 🟢 | 🟢 Media | **~7h** |
| Cortex + Paz + Memoria | 🟢 3/3 | 🟢 Alta | **~28h** |
| HUD + Tests + CI/CD | 🟡 | 🟡 Media | **~38h** |
| **TOTAL** | **21/54 🟢** | | **~191h** |
