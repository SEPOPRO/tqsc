"""
tqsc/utils/siem.py — Nivel 4: Syslog forwarding (RFC 3164) + alertas SIEM.
"""
import logging, socket, os, json, threading, time
from datetime import datetime

LOG = logging.getLogger("tqsc.siem")

class SyslogForwarder:
    """Envía eventos TQSC a syslog (RFC 3164 / BSD style)."""

    MAX_BUFFER = 10000

    def __init__(self, host: str = "127.0.0.1", port: int = 514,
                 app_name: str = "TQSC", facility: int = 1):  # 1 = user-level
        self.host = host
        self.port = port
        self.app = app_name
        self.facility = facility
        self._sock: socket.socket | None = None
        self._activo = False
        self._buffer: list[str] = []
        self._hilo: threading.Thread | None = None

    def _conectar(self):
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.settimeout(2)
            self._sock.connect((self.host, self.port))
            return True
        except (OSError, socket.gaierror) as e:
            LOG.debug("Syslog no disponible: %s", e)
            return False

    def _rfc3164(self, severity: int, msg: str) -> bytes:
        """RFC 3164: <PRI>timestamp hostname app[PID]: msg"""
        pri = self.facility * 8 + severity
        ts = datetime.now().strftime("%b %d %H:%M:%S")
        return f"<{pri}>{ts} TQSC {self.app}[{os.getpid()}]: {msg}\n".encode()

    def enviar(self, severity: int, msg: str):
        """severity: 0=emerg, 1=alert, 2=crit, 3=err, 4=warning, 5=notice, 6=info, 7=debug"""
        if not self._sock:
            if not self._conectar():
                if len(self._buffer) < self.MAX_BUFFER:
                    self._buffer.append(msg)
                return
        try:
            self._sock.send(self._rfc3164(severity, msg))
        except OSError:
            self._sock = None
            self._buffer.append(msg)

    def flush(self):
        """Envía buffer acumulado."""
        if not self._buffer:
            return
        if not self._sock and not self._conectar():
            return
        pendientes = list(self._buffer)
        self._buffer.clear()
        for msg in pendientes:
            self.enviar(3, msg)  # err level for buffered

    def iniciar(self):
        self._activo = True
        if self._buffer:
            self.flush()

    def detener(self):
        self._activo = False
        self.flush()


class AlertEngine:
    """Engine de alertas multicanal: log + syslog + callback."""

    def __init__(self, syslog: SyslogForwarder | None = None):
        self.syslog = syslog
        self._callbacks: list[callable] = []

    def registrar_callback(self, fn: callable):
        self._callbacks.append(fn)

    def alertar(self, nivel: str, modulo: str, mensaje: str):
        """Dispara alerta a todos los canales."""
        sev_map = {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 4, "LOW": 5}
        sev = sev_map.get(nivel.upper(), 6)
        sev_idx = max(0, min(sev - 2, 3))
        log_levels = ["critical", "error", "warning", "info"]
        getattr(LOG, log_levels[sev_idx])("[%s] %s: %s", nivel, modulo, mensaje)

        # Syslog
        if self.syslog:
            self.syslog.enviar(sev, f"[{nivel}][{modulo}] {mensaje}")

        # Callbacks
        for cb in self._callbacks:
            try:
                cb({"nivel": nivel, "modulo": modulo, "mensaje": mensaje,
                    "timestamp": datetime.now().isoformat()})
            except Exception:
                pass


# Instancia global
_syslog = SyslogForwarder()
_alertas = AlertEngine(_syslog)


def obtener_syslog() -> SyslogForwarder: return _syslog
def obtener_alertas() -> AlertEngine: return _alertas
