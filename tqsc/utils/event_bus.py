"""TQSC v2.0 — Bus de eventos en vivo para el HUD."""
import threading, json, time
from collections import deque, defaultdict
from datetime import datetime

_lock = threading.Lock()
_cola: deque[dict] = deque(maxlen=500)
_metricas: dict = {
    "cpu": 0, "ram": 0, "entropia": 0.5,
    "octantes": 8, "octantes_aislados": 0,
    "nodos_blockchain": 0, "sesiones_honeypot": 0,
    "severidad": "INFORMATIONAL", "ataques_hoy": 0,
    "modelo_ml": "NO DISPONIBLE", "rust": "tqsc_native v0.1.0",
    "cifrado": "AES-256-GCM", "boot": "INTEGRIDAD OK",
    "geonoise": "WiFi + OSM",
    "uptime": int(time.time()),
    "timestamp": datetime.now().strftime("%H:%M:%S"),
    "nucleos": {},
}

_actividad_nucleos: dict[str, dict] = defaultdict(lambda: {
    "estado": "standby", "ultimo_evento": "", "ultima_accion": "",
    "metricas": {}, "alertas": 0,
})


def evento(tipo: str, nucleo: str, accion: str,
            detalle: str = "", severidad: str = "info",
            resultado: str = ""):
    """Registra un evento real de un núcleo TQSC."""
    ev = {
        "t": tipo, "n": nucleo, "a": accion, "d": detalle,
        "s": severidad, "r": resultado,
        "h": datetime.now().strftime("%H:%M:%S"),
        "ts": time.time(),
    }
    with _lock:
        _cola.appendleft(ev)
        _actividad_nucleos[nucleo]["estado"] = "activo"
        _actividad_nucleos[nucleo]["ultimo_evento"] = accion
        _actividad_nucleos[nucleo]["ultima_accion"] = f"{tipo}: {detalle}"
        _actividad_nucleos[nucleo]["alertas"] += 1
        _metricas["severidad"] = _calcular_severidad()


def actualizar_nucleo(nombre: str, estado: str, metricas: dict = None):
    """Actualiza estado de un núcleo específico."""
    with _lock:
        _actividad_nucleos[nombre]["estado"] = estado
        if metricas:
            _actividad_nucleos[nombre]["metricas"].update(metricas)


def actualizar_metricas(clave: str, valor):
    """Actualiza una métrica del sistema."""
    with _lock:
        _metricas[clave] = valor
        _metricas["timestamp"] = datetime.now().strftime("%H:%M:%S")
        _metricas["uptime"] = int(time.time())


def _calcular_severidad() -> str:
    eventos = list(_cola)
    crits = sum(1 for e in eventos if e.get("s") == "crit")
    warns = sum(1 for e in eventos if e.get("s") == "warn")
    if crits >= 3: return "CRITICAL"
    if crits >= 1: return "HIGH"
    if warns >= 5: return "MEDIUM"
    if warns >= 1: return "LOW"
    return "INFORMATIONAL"


def obtener_estado() -> dict:
    """Devuelve estado completo + últimos eventos + actividad por núcleo."""
    with _lock:
        _metricas["ataques_hoy"] = len([e for e in _cola if e.get("t") == "ataque"])
        return {
            **_metricas,
            "nucleos": dict(_actividad_nucleos),
            "eventos": list(_cola)[:50],
        }
