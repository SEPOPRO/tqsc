"""
tqsc/deception/honeyfiles.py — Archivos señuelo con monitoreo SHA256.
"""
import logging, threading, time, hashlib, secrets
from pathlib import Path
from typing import Optional
from .storage import SQLiteStorage
from .alert_engine import AlertEngine

LOG = logging.getLogger("tqsc.deception.honeyfiles")


class HoneyFiles:
    """Archivos señuelo plantados en directorios reales con verificación SHA256 periódica."""

    def __init__(self, storage: SQLiteStorage, alerts: AlertEngine):
        self._storage = storage
        self._alerts = alerts
        self._archivos: dict[str, str] = {}
        self._activo = False
        self._hilo: Optional[threading.Thread] = None

    def plantar(self, directorios: list[str] = None) -> list[str]:
        targets = directorios or [
            str(Path.home() / "Documents"), str(Path.home() / "Desktop"),
            str(Path.home() / ".ssh"), "data",
        ]
        creados = []
        for d in targets:
            try:
                p = Path(d)
                if not p.exists():
                    continue
                for nombre in ["credentials.txt", "backup_db.sql", "master.key"][:2]:
                    archivo = p / f".{secrets.token_hex(4)}_{nombre}"
                    contenido = f"### {nombre} - DO NOT SHARE\nadmin_pass = {secrets.token_urlsafe(20)}\ndb_pass = {secrets.token_urlsafe(24)}\n"
                    archivo.write_text(contenido)
                    self._archivos[str(archivo)] = hashlib.sha256(contenido.encode()).hexdigest()[:16]
                    creados.append(str(archivo))
                    LOG.debug("📄 HoneyFile: %s", archivo)
            except (OSError, PermissionError):
                continue
        LOG.info("📄 %d HoneyFiles plantados", len(creados))
        return creados

    def verificar(self) -> list[dict]:
        alterados = []
        for ruta_str, hash_orig in list(self._archivos.items()):
            p = Path(ruta_str)
            if not p.exists():
                self._alerts.disparar({"tipo": "honeyfile_eliminado", "componente": "honeyfiles",
                                        "detalle": ruta_str, "severidad": "alta"})
                alterados.append(ruta_str)
                LOG.critical("🚨 HONEYFILE ELIMINADO: %s", ruta_str)
            else:
                h = hashlib.sha256(p.read_bytes()).hexdigest()[:16]
                if h != hash_orig:
                    self._alerts.disparar({"tipo": "honeyfile_modificado", "componente": "honeyfiles",
                                            "detalle": ruta_str, "severidad": "critica"})
                    alterados.append(ruta_str)
                    LOG.critical("🚨 HONEYFILE MODIFICADO: %s", ruta_str)
                    self._archivos[ruta_str] = h
        return alterados

    def iniciar(self):
        if self._activo:
            return
        self._activo = True

        def loop():
            while self._activo:
                try:
                    self.verificar()
                except Exception:
                    pass
                time.sleep(30)

        self._hilo = threading.Thread(target=loop, daemon=True, name="HoneyFiles")
        self._hilo.start()
        LOG.info("📁 HoneyFiles monitor activo")

    def detener(self):
        self._activo = False
