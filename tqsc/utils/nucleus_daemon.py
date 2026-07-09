"""TQSC v2.0 — NucleusDaemon con mTLS opcional."""
import time, json, socket, threading, logging, os, signal, ssl
from pathlib import Path
from typing import Optional

LOG = logging.getLogger("tqsc.daemon")

TLS_DISABLED = os.environ.get("TQSC_TLS_DISABLE") == "1"


def _tls_wrapper(nombre: str):
    """Retorna TLSWrapper si hay certificados disponibles."""
    if TLS_DISABLED:
        return None
    try:
        from utils.tls import TLSWrapper
        certs_dir = Path(os.environ.get("TQSC_HOME", "data")) / "certs"
        ca = certs_dir / "ca.crt"
        cert = certs_dir / f"{nombre}.crt"
        key = certs_dir / f"{nombre}.key"
        if ca.exists() and cert.exists() and key.exists():
            return TLSWrapper(ca.read_bytes(), cert.read_bytes(), key.read_bytes())
    except Exception:
        pass
    return None


class NucleusDaemon:
    """Wrapper para núcleo como proceso independiente, con mTLS opcional."""

    def __init__(self, nombre: str, puerto: int, heartbeat_interval: int = 5):
        self.nombre = nombre; self.puerto = puerto
        self._heartbeat_interval = heartbeat_interval
        self._nucleo = None; self._activo = False
        self._server: Optional[socket.socket] = None
        self._tls = _tls_wrapper(nombre)
        if self._tls:
            LOG.info("Daemon %s: mTLS activo", nombre)
        else:
            LOG.info("Daemon %s: sin TLS (sin certificados o deshabilitado)", nombre)

    def iniciar(self, nucleo):
        self._nucleo = nucleo; self._activo = True
        print(f"DAEMON_INIT:{self.nombre}:{self.puerto}")
        LOG.info("Daemon %s iniciado en puerto %d", self.nombre, self.puerto)

    def loop(self):
        hilo_heartbeat = threading.Thread(target=self._heartbeat_loop, daemon=True)
        hilo_heartbeat.start()
        # Abrir socket TLS si hay certificados
        if self._tls:
            try:
                self._server = self._tls.escuchar(self.puerto, self._manejar_conexion)
                hilo_srv = threading.Thread(target=self._aceptar_conexiones, daemon=True)
                hilo_srv.start()
            except Exception as e:
                LOG.warning("Daemon %s: no se pudo abrir TLS: %s", self.nombre, e)
        while self._activo:
            try: time.sleep(0.5)
            except KeyboardInterrupt: self._detener(); break

    def _aceptar_conexiones(self):
        while self._activo and self._server:
            try:
                conn, addr = self._server.accept()
                LOG.debug("Conexión TLS de %s", addr)
            except: break

    def _manejar_conexion(self, conn):
        conn.close()

    def _heartbeat_loop(self):
        while self._activo:
            print("HEARTBEAT", flush=True)
            time.sleep(self._heartbeat_interval)

    def _detener(self):
        self._activo = False
        print(f"DAEMON_STOP:{self.nombre}")
        LOG.info("Daemon %s detenido", self.nombre)

