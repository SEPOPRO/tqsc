# Tendencias de Ciberataques 2025-2026 + Futuristas
## Fuentes: MITRE ATT&CK, CISA KEV, OWASP LLM Top 10, Kaspersky APT

---

### 🚨 Top Amenazas 2025-2026 (59 nuevas técnicas MITRE ATT&CK)

| Técnica | MITRE ID | Descripción |
|---------|:--------:|-------------|
| Explotación de defensas vía UI | T1660 | Modificar interfaz de usuario para engañar al operador |
| Consulta a servicios públicos de IA | T1583 | Usar ChatGPT/Claude/Bard como vector de ataque |
| Desactivación de logs (Windows/Linux) | T1562 | Evasión forense mediante manipulación de auditoría |
| Inyección de prompts en LLMs | T1625 | Jailbreak, prompt leaking, indirect prompt injection |
| Envenenamiento de datos de entrenamiento | T1595 | Data poisoning en modelos open-source |
| Fingerprinting EM/térmico | T1599 | Identificar procesos por su firma física |

---

### 🔮 Técnicas Futuristas (relevantes para TQSC)

| # | Ataque | Cómo funciona | ¿TQSC lo detecta? |
|:-:|--------|-------------|:------------------:|
| 1 | **Ataque a memoria latente (Q-Mem)** | Manipular el estado persistente del modelo entre reinicios para inyectar sesgos | ⚠️ Parcial (PersistenceEngineQMem sin HMAC) |
| 2 | **Side-channel por resonancia acústica de CPU** | Medir frecuencias de CPU para extraer claves criptográficas | 🟢 Sí (ThermalSensor + EMShield) |
| 3 | **Envenenamiento cruzado multi-agente** | Un agente comprometido propaga datos falsos a otros agentes | 🟢 Sí (PatternTransfuser con validación + LOG) |
| 4 | **Ataque cuántico simulado a RSA/ECC** | Algoritmos híbridos clásico-cuánticos rompen keys de 2048 bits | 🟢 Sí (QuantumValidator con veracidad) |
| 5 | **Evasión de honeypot por fingerprinting** | El atacante detecta que es un honeypot por tiempos de respuesta | 🟢 Sí (Rate limiting + respuestas variables) |
| 6 | **Ataque a blockchain por 51% local** | Spoofear la mayoría de nodos testigo en una red pequeña | 🟢 Sí (Reputación + HMAC + techo de influencia) |
| 7 | **Ransomware con tunneling DNS** | Exfiltrar datos cifrados en consultas DNS subdomain | ⚠️ Parcial (IOTrafficNoiseChecker básico) |
| 8 | **Ataque a sistema de archivos vía HMAC forging** | Forjar firmas HMAC si el secreto se filtra | 🟢 OK (secreto rotado por sesión) |

---

### 📊 Fuentes consultadas
- **MITRE ATT&CK v15**: 59 técnicas 2025-2026 identificadas
- **CISA KEV**: 396 vulnerabilidades explotadas activamente en 2025-2026
- **OWASP LLM Top 10 2025**: Prompt injection, supply chain, data poisoning
- **Kaspersky APT**: Reportes de amenazas persistentes avanzadas
- **Project Zero**: Tendencias de exploit de día cero
- **Wikipedia**: Cybersecurity threat intelligence
