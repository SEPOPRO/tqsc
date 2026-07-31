"""
tqsc/deception/honeycreds.py — Credenciales señuelo reales del SO con strategy pattern.
"""
import logging, secrets, threading, time
from typing import Optional
from .storage import SQLiteStorage
from .alert_engine import AlertEngine
from .strategies import get_strategy

LOG = logging.getLogger("tqsc.deception.honeycreds")


class HoneyCredentials:
    """Crea y monitorea usuarios reales del SO con shell restringido."""

    def __init__(self, storage: SQLiteStorage, alerts: AlertEngine):
        self._storage = storage
        self._alerts = alerts
        self._usuarios: dict[str, str] = {}
        self._strategy = get_strategy()

    def generar_lote(self, cantidad: int = 3) -> list[dict]:
        creados = []
        for _ in range(cantidad):
            nombre = f"svc_{secrets.token_hex(4)}"
            pwd = secrets.token_urlsafe(16)
            ok = self._strategy.crear_usuario(nombre, pwd)
            if ok:
                self._usuarios[nombre] = pwd
                creados.append({"usuario": nombre, "password": pwd})
                LOG.info("🔹 HoneyUser real: %s", nombre)
        return creados

    def verificar_login(self, usuario: str, password: str) -> Optional[str]:
        if usuario in self._usuarios and self._usuarios[usuario] == password:
            self._alerts.disparar({"tipo": "honey_cred", "componente": "honeycreds",
                                    "detalle": f"Credencial usada: {usuario}", "severidad": "critica"})
            LOG.critical("🚨 HONEY CRED USADA: %s", usuario)
            return usuario
        return None

    def audit_logins(self):
        alertas = self._strategy.auditar_logins(list(self._usuarios.keys()))
        for a in alertas:
            self._alerts.disparar({"tipo": "honey_cred", "componente": "honeycreds",
                                    "detalle": a, "severidad": "critica"})

    def eliminar_todos(self):
        for nombre in list(self._usuarios.keys()):
            self._strategy.eliminar_usuario(nombre)
            LOG.info("🧹 HoneyUser eliminado: %s", nombre)
        self._usuarios.clear()

    def iniciar(self):
        """Inicia auditoría periódica de logins."""
        def loop():
            while True:
                try:
                    self.audit_logins()
                except Exception:
                    pass
                time.sleep(120)
        threading.Thread(target=loop, daemon=True, name="HoneyCredAudit").start()
        LOG.info("🔑 HoneyCreds auditoría activa")

    def detener(self):
        self.eliminar_todos()
