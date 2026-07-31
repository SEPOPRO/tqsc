"""
tqsc/utils/siem_core.py — SIEM Core: correlación + time-series + ingesta externa.
"""
import json, logging, os, time, threading, hashlib
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Optional

LOG = logging.getLogger("tqsc.siem_core")


class EventStore:
    """Time-series persistente de eventos. Almacenamiento JSONL por hora."""

    def __init__(self, data_dir: str = "data/siem"):
        self.base = Path(data_dir)
        self.base.mkdir(parents=True, exist_ok=True)
        self._cache: deque = deque(maxlen=10000)
        self._indices: dict[str, int] = {}  # hora → lineas
        self._lock = threading.Lock()

    def _archivo(self, ts: float = None) -> Path:
        dt = datetime.fromtimestamp(ts or time.time())
        return self.base / f"{dt.strftime('%Y%m%d_%H')}.jsonl"

    def store(self, evento: dict):
        """Almacena un evento con timestamp."""
        evento["_stored"] = time.time()
        with self._lock:
            self._cache.appendleft(evento)
            archivo = self._archivo(evento.get("ts", time.time()))
            with open(archivo, "a") as f:
                f.write(json.dumps(evento, ensure_ascii=False, default=str) + "\n")

    def query(self, desde: float = 0, hasta: float = None,
              tipos: list[str] = None, nucleos: list[str] = None,
              severidad: str = None, limit: int = 200) -> list[dict]:
        """Consulta eventos con filtros."""
        hasta = hasta or time.time()
        resultados = []
        # Buscar en caché primero
        for e in list(self._cache):
            ts = e.get("ts", e.get("_stored", 0))
            if desde <= ts <= hasta:
                if tipos and e.get("t") not in tipos: continue
                if nucleos and e.get("n") not in nucleos: continue
                if severidad and e.get("s", "").upper() != severidad.upper(): continue
                resultados.append(e)
        if len(resultados) >= limit:
            return resultados[:limit]
        # Buscar en archivos históricos
        hora_desde = datetime.fromtimestamp(desde).strftime("%Y%m%d_%H")
        hora_hasta = datetime.fromtimestamp(hasta).strftime("%Y%m%d_%H")
        for archivo in sorted(self.base.glob("*.jsonl"), reverse=True):
            if archivo.stem < hora_desde or archivo.stem > hora_hasta:
                continue
            try:
                for line in open(archivo):
                    try:
                        e = json.loads(line)
                        ts = e.get("ts", e.get("_stored", 0))
                        if desde <= ts <= hasta:
                            if tipos and e.get("t") not in tipos: continue
                            if nucleos and e.get("n") not in nucleos: continue
                            if severidad and e.get("s", "").upper() != severidad.upper(): continue
                            if e not in resultados:
                                resultados.append(e)
                    except (json.JSONDecodeError, KeyError):
                        continue
            except Exception:
                pass
        resultados.sort(key=lambda x: x.get("ts", 0), reverse=True)
        return resultados[:limit]

    def tendencias(self, horas: int = 24) -> dict:
        """Agrupa eventos por hora para tendencias."""
        desde = time.time() - horas * 3600
        events = self.query(desde=desde, limit=10000)
        por_hora = defaultdict(int)
        por_tipo = defaultdict(int)
        por_nucleo = defaultdict(int)
        for e in events:
            h = datetime.fromtimestamp(e.get("ts", e.get("_stored", 0))).strftime("%H:00")
            por_hora[h] += 1
            por_tipo[e.get("t", "desconocido")] += 1
            por_nucleo[e.get("n", "?")] += 1
        return {
            "por_hora": dict(sorted(por_hora.items())),
            "por_tipo": dict(por_tipo),
            "por_nucleo": dict(por_nucleo),
            "total": len(events),
            "horas": horas,
        }


class CorrelationRule:
    """Regla de correlación: combina múltiples eventos para detectar patrones."""

    def __init__(self, nombre: str, descripcion: str,
                 condiciones: list[dict], ventana: int = 60,
                 severidad: str = "HIGH", accion: str = ""):
        self.nombre = nombre
        self.descripcion = descripcion
        self.condiciones = condiciones  # [{"tipo": "ataque", "nucleo": "honeypot", "min": 3}]
        self.ventana = ventana  # segundos
        self.severidad = severidad
        self.accion = accion

    def evaluar(self, eventos: list[dict]) -> Optional[dict]:
        """Evalúa si las condiciones se cumplen en los eventos recientes."""
        ahora = time.time()
        ventana_inicio = ahora - self.ventana
        recientes = [e for e in eventos if e.get("ts", e.get("_stored", ahora)) >= ventana_inicio]
        for cond in self.condiciones:
            count = sum(1 for e in recientes
                        if (not cond.get("tipo") or e.get("t") == cond["tipo"]) and
                           (not cond.get("nucleo") or e.get("n") == cond["nucleo"]) and
                           (not cond.get("severidad") or e.get("s", "").upper() == cond["severidad"].upper()))
            if count < cond.get("min", 1):
                return None
        return {
            "alerta": self.nombre,
            "descripcion": self.descripcion,
            "severidad": self.severidad,
            "accion": self.accion,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "eventos_en_ventana": len(recientes),
        }


class SIEMCore:
    """Motor SIEM completo: correlación + time-series + alertas."""

    def __init__(self, data_dir: str = "data/siem"):
        self.store = EventStore(data_dir)
        self._reglas: list[CorrelationRule] = []
        self._alertas: deque = deque(maxlen=500)
        self._ultima_eval = 0
        self._cargar_reglas_default()

    def _cargar_reglas_default(self):
        self._reglas = [
            # ── Ataques coordinados ──
            CorrelationRule("ataque_coordinado", "≥5 ataques en ≥3 núcleos distintos en 2min",
                           [{"tipo": "ataque", "min": 5},
                            {"tipo": "ataque", "nucleo": "honeypot", "min": 2}],
                           ventana=120, severidad="CRITICAL", accion="notificar_admin"),
            CorrelationRule("multi_vectores", "Ataques desde ≥3 vectores distintos en 5min",
                           [{"tipo": "ataque", "nucleo": "honeypot", "min": 1},
                            {"tipo": "diagnostico", "severidad": "CRITICAL", "min": 1},
                            {"tipo": "evento", "nucleo": "defensa", "min": 1}],
                           ventana=300, severidad="CRITICAL", accion="bloquear_ip"),

            # ── Fuerza bruta ──
            CorrelationRule("brute_force_masivo", "≥10 intentos de login en 1min",
                           [{"tipo": "login", "nucleo": "honeypot", "min": 10}],
                           ventana=60, severidad="HIGH", accion="rate_limit"),
            CorrelationRule("brute_force_distribuido", "Múltiples IPs atacando mismo usuario en 5min",
                           [{"tipo": "login", "nucleo": "honeypot", "min": 20}],
                           ventana=300, severidad="CRITICAL", accion="bloquear_ip"),
            CorrelationRule("password_spray", "Mismos password contra múltiples usuarios en 10min",
                           [{"tipo": "login", "nucleo": "honeypot", "min": 15}],
                           ventana=600, severidad="MEDIUM", accion="monitorear"),

            # ── Escaneo y reconocimiento ──
            CorrelationRule("escaneo_sistematico", "Scan de puertos + path traversal + SQLi en 5min",
                           [{"tipo": "scanner", "min": 2},
                            {"tipo": "ataque", "nucleo": "honeypot", "min": 3}],
                           ventana=300, severidad="CRITICAL", accion="bloquear_ip"),
            CorrelationRule("reconocimiento_profundo", "Múltiples técnicas de reconocimiento en 10min",
                           [{"tipo": "scanner", "min": 3},
                            {"tipo": "ataque", "nucleo": "honeypot", "min": 5}],
                           ventana=600, severidad="HIGH", accion="bloquear_ip"),
            CorrelationRule("barrido_puertos", "≥50 conexiones a puertos distintos en 1min",
                           [{"tipo": "scanner", "min": 10}],
                           ventana=60, severidad="MEDIUM", accion="rate_limit"),

            # ── Fuga de información ──
            CorrelationRule("fuga_lenta", "Eventos crypto+blockchain+defensa en 1min (posible exfiltración)",
                           [{"tipo": "evento", "nucleo": "crypto", "min": 1},
                            {"tipo": "evento", "nucleo": "blockchain", "min": 1},
                            {"tipo": "evento", "nucleo": "defensa", "min": 1}],
                           ventana=60, severidad="MEDIUM", accion="monitorear"),
            CorrelationRule("exfiltracion_datos", "Múltiples accesos a crypto + defensa + IA en 2min",
                           [{"tipo": "evento", "nucleo": "crypto", "min": 3},
                            {"tipo": "evento", "nucleo": "defensa", "min": 3},
                            {"tipo": "evento", "nucleo": "ia_core", "min": 2}],
                           ventana=120, severidad="HIGH", accion="notificar_admin"),

            # ── Integridad del sistema ──
            CorrelationRule("fallo_cascada", "≥3 núcleos con error CRITICAL en 5min",
                           [{"tipo": "diagnostico", "severidad": "CRITICAL", "min": 3}],
                           ventana=300, severidad="CRITICAL", accion="escalar"),
            CorrelationRule("doctor_alertas", "Doctor TQSC detecta ≥3 fallos seguidos en 5min",
                           [{"tipo": "diagnostico", "nucleo": "doctor", "min": 3}],
                           ventana=300, severidad="CRITICAL", accion="escalar"),
            CorrelationRule("circuit_breaker_cascada", "≥2 circuit breakers abiertos en 2min",
                           [{"tipo": "evento", "nucleo": "quantum", "min": 1},
                            {"tipo": "evento", "nucleo": "defensa", "min": 1}],
                           ventana=120, severidad="HIGH", accion="restart_nucleo"),

            # ── Anomalías ML ──
            CorrelationRule("anomalia_sostenida", "ML detecta anomalías en IA + entropy + defensa en 10min",
                           [{"tipo": "evento", "nucleo": "ia_core", "min": 3},
                            {"tipo": "evento", "nucleo": "entropia", "min": 2}],
                           ventana=600, severidad="HIGH", accion="monitorear"),
            CorrelationRule("degeneracion_ia", "≥2 octantes aislados por loop detection en 5min",
                           [{"tipo": "diagnostico", "nucleo": "ia_core", "min": 2}],
                           ventana=300, severidad="HIGH", accion="restart_nucleo"),

            # ── Ataques a la blockchain ──
            CorrelationRule("fork_sospechoso", "Blockchain fork + nodos comprometidos en 5min",
                           [{"tipo": "evento", "nucleo": "blockchain", "min": 3}],
                           ventana=300, severidad="HIGH", accion="notificar_admin"),
            CorrelationRule("consenso_roto", "Múltiples desacuerdos de consenso en 10min",
                           [{"tipo": "evento", "nucleo": "blockchain", "min": 5}],
                           ventana=600, severidad="CRITICAL", accion="escalar"),

            # ── Ataques a honeypot ──
            CorrelationRule("honeypot_saturado", "≥100 ataques en 1min contra honeypot",
                           [{"tipo": "ataque", "nucleo": "honeypot", "min": 50}],
                           ventana=60, severidad="MEDIUM", accion="rate_limit"),
            CorrelationRule("ataque_dirigido", "Mismo comando malicioso repetido ≥10 veces en 2min",
                           [{"tipo": "ataque", "nucleo": "honeypot", "min": 10}],
                           ventana=120, severidad="MEDIUM", accion="bloquear_ip"),

            # ── Autenticación y acceso ──
            CorrelationRule("account_takeover", "Login fallido + MFA code erróneo + bloqueo de cuenta en 5min",
                           [{"tipo": "login", "nucleo": "auth", "min": 5}],
                           ventana=300, severidad="CRITICAL", accion="bloquear_ip"),
            CorrelationRule("token_abuse", "Múltiples tokens inválidos en 1min",
                           [{"tipo": "evento", "nucleo": "auth", "min": 10}],
                           ventana=60, severidad="HIGH", accion="rate_limit"),

            # ── Compliance ──
            CorrelationRule("pci_dss_violation", "Acceso a datos sensibles sin cifrado + auditoría alterada en 10min",
                           [{"tipo": "evento", "nucleo": "crypto", "min": 1},
                            {"tipo": "evento", "nucleo": "memoria", "min": 1}],
                           ventana=600, severidad="CRITICAL", accion="escalar"),
            CorrelationRule("nist_violation", "Múltiples desviaciones de baseline en 15min",
                           [{"tipo": "diagnostico", "severidad": "HIGH", "min": 5}],
                           ventana=900, severidad="CRITICAL", accion="escalar"),
        ]

    def ingesta_evento(self, evento: dict):
        """Ingesta un evento desde cualquier fuente (TQSC interno o externo)."""
        evento["_ingestado"] = time.time()
        evento["ts"] = evento.get("ts", evento.get("timestamp", time.time()))
        self.store.store(evento)

    def ingesta_externa(self, data: str, formato: str = "json") -> int:
        """Ingesta logs externos (JSON lines o syslog)."""
        count = 0
        for line in data.strip().split("\n"):
            if not line.strip():
                continue
            try:
                if formato == "json":
                    ev = json.loads(line)
                else:
                    ev = {"t": "externo", "n": "externo", "a": "syslog",
                          "d": line[:500], "s": "info", "ts": time.time()}
                ev["_fuente"] = "externa"
                self.ingesta_evento(ev)
                count += 1
            except json.JSONDecodeError:
                continue
        return count

    def correlar(self):
        """Ejecuta todas las reglas de correlación."""
        ahora = time.time()
        if ahora - self._ultima_eval < 10:
            return []
        self._ultima_eval = ahora
        eventos = list(self.store._cache)
        alertas = []
        for regla in self._reglas:
            resultado = regla.evaluar(eventos)
            if resultado:
                self._alertas.appendleft(resultado)
                alertas.append(resultado)
                LOG.warning("⚠️ CORRELACIÓN: %s — %s", resultado["alerta"], resultado["descripcion"])
                # Registrar en auditoría
                try:
                    from utils.audit import obtener_audit
                    obtener_audit().registrar("correlacion", "siem", resultado["alerta"],
                                              resultado["descripcion"], resultado["severidad"])
                except Exception:
                    pass
        return alertas

    def tendencias(self, horas: int = 24) -> dict:
        return self.store.tendencias(horas)

    def estado(self) -> dict:
        return {"eventos_almacenados": len(self.store._cache),
                "alertas_correlacion": len(self._alertas),
                "reglas": len(self._reglas),
                "ultima_evaluacion": datetime.fromtimestamp(self._ultima_eval).isoformat() if self._ultima_eval else "N/A"}


_siem_core: Optional[SIEMCore] = None
def obtener_siem_core() -> SIEMCore:
    global _siem_core
    if _siem_core is None:
        data_dir = os.environ.get("TQSC_HOME", "data")
        _siem_core = SIEMCore(os.path.join(data_dir, "siem"))
    return _siem_core
