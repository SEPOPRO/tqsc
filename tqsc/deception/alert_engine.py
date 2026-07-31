"""
tqsc/deception/alert_engine.py — Motor de alertas con correlación, persistencia y MITRE mapping.
"""
import logging, time, hashlib, hmac, json, threading, os, secrets
from typing import Optional
from .models import Alerta, EventoCorrelacion
from .storage import SQLiteStorage
from .interfaces import IAlertEngine

LOG = logging.getLogger("tqsc.deception.alert")

# MITRE ATT&CK mappings para detecciones de deception
MITRE_MAP = {
    "honeytoken":         {"tipo": "T1556", "nombre": "Modify Authentication Process"},
    "honey_cred":         {"tipo": "T1003", "nombre": "OS Credential Dumping"},
    "canary_dns":         {"tipo": "T1071.004", "nombre": "DNS"},
    "canary_http":        {"tipo": "T1071.001", "nombre": "Web Protocols"},
    "honeyfile_acceso":   {"tipo": "T1005", "nombre": "Data from Local System"},
    "honeyfile_mod":      {"tipo": "T1565", "nombre": "Data Manipulation"},
    "tarpit":             {"tipo": "T1046", "nombre": "Network Service Scanning"},
}


class CorrelationRule:
    """Regla de correlación entre múltiples alertas."""

    def __init__(self, nombre: str, patrones: list[str], ventana: float,
                 severidad: str, mitre: str, desc: str):
        self.nombre = nombre
        self.patrones = patrones
        self.ventana = ventana
        self.severidad = severidad
        self.mitre = mitre
        self.desc = desc

    def evaluar(self, alertas: list[dict]) -> Optional[EventoCorrelacion]:
        ahora = time.time()
        candidatos = [a for a in alertas if ahora - a.get("ts", 0) <= self.ventana
                      and a.get("tipo") in self.patrones]
        if len(candidatos) >= 2:
            return EventoCorrelacion(
                alertas=[a["id"] for a in candidatos],
                patron=self.nombre,
                confidence=min(1.0, len(candidatos) * 0.3),
                mitre_attack=[self.mitre],
                ts=ahora)
        return None


class AlertEngine(IAlertEngine):
    """Motor de alertas con correlación, firma HMAC, persistencia SQLite."""

    def __init__(self, storage: SQLiteStorage, secreto: str = ""):
        self._storage = storage
        self._secreto = secreto or os.environ.get("TQSC_DECEPTION_SECRET", secrets.token_hex(16))
        self._lock = threading.Lock()
        self._alertas_recientes: list[dict] = []
        self._callback_siem: Optional[callable] = None
        self._callback_hud: Optional[callable] = None
        self._hooks: list[callable] = []  # ABH hooks

        self._reglas = [
            CorrelationRule("reconocimiento_profundo", ["canary_dns", "tarpit"], 300, "alta", "T1595", "Reconocimiento activo"),
            CorrelationRule("credential_harvesting", ["honeytoken", "honey_cred"], 600, "critica", "T1003", "Robo de credenciales"),
            CorrelationRule("ataque_coordinado", ["honeytoken", "canary_dns", "canary_http"], 900, "critica", "T1190", "Ataque multi-vector"),
            CorrelationRule("exfiltracion", ["honeyfile_acceso", "honeyfile_mod"], 300, "alta", "T1041", "Posible exfiltración"),
        ]

    def conectar_siem(self, cb: callable):
        self._callback_siem = cb

    def conectar_hud(self, cb: callable):
        self._callback_hud = cb

    def register_hook(self, cb: callable):
        """Registra un hook que se ejecuta cada vez que se dispara una alerta.
        Usado por ABH Engine para feedback automático."""
        self._hooks.append(cb)

    def disparar(self, alerta: dict) -> str:
        """Dispara una alerta: persiste, firma, correlaciona, callback."""
        a = Alerta(tipo=alerta.get("tipo", "desconocido"),
                   componente=alerta.get("componente", ""),
                   detalle=alerta.get("detalle", ""),
                   severidad=alerta.get("severidad", "media"),
                   origen=alerta.get("origen", ""),
                   ts=time.time())
        a.firmar(self._secreto)
        self._storage.guardar_alerta(a)

        with self._lock:
            self._alertas_recientes.append(a.to_dict())
            if len(self._alertas_recientes) > 500:
                self._alertas_recientes = self._alertas_recientes[-250:]

        # Correlacionar
        evento = self.correlacionar(a.to_dict())
        if evento:
            LOG.critical("🧠 CORRELACIÓN: %s (confianza=%.2f) — MITRE %s",
                         evento.patron, evento.confidence, evento.mitre_attack)

        # Callbacks
        if self._callback_siem:
            try: self._callback_siem(a.to_dict())
            except: pass
        if self._callback_hud:
            try: self._callback_hud(a.to_dict())
            except: pass
        # ABH Hooks
        for hook in self._hooks:
            try: hook(alerta)
            except Exception as e:
                LOG.debug("Hook error: %s", e)

        return a.id

    def correlacionar(self, alerta: dict) -> Optional[EventoCorrelacion]:
        """Evalúa reglas de correlación contra alertas recientes."""
        with self._lock:
            for regla in self._reglas:
                r = regla.evaluar(self._alertas_recientes + [alerta])
                if r:
                    return r
        return None

    def alertas(self, tipo: str = "", limite: int = 100, desde_ts: float = 0) -> list[dict]:
        return self._storage.consultar_alertas(tipo, limite, desde_ts)

    def contar(self, desde_ts: float = 0) -> int:
        return self._storage.contar_alertas(desde_ts)

    def estado(self) -> dict:
        return {"alertas_totales": self.contar(time.time() - 86400),
                "reglas_correlacion": len(self._reglas),
                "mitre_mappings": len(MITRE_MAP)}
