"""
tqsc/deception/canary_http.py — Servidor HTTP señuelo con fingerprinting.
"""
import logging, socket, threading
from .alert_engine import AlertEngine

LOG = logging.getLogger("tqsc.deception.canary_http")


class CanaryHTTP:
    """Servidor HTTP señuelo que captura IP, UA, método, path."""

    def __init__(self, alerts: AlertEngine, puerto: int = 8088):
        self._alerts = alerts
        self.puerto = puerto
        self._activo = False
        self._pool = threading.BoundedSemaphore(50)

    def _handle(self, conn, addr):
        with self._pool:
            try:
                data = conn.recv(4096)
                if not data:
                    return
                texto = data.decode("utf-8", errors="replace")
                lines = texto.split("\r\n")
                req = lines[0] if lines else ""
                ua = ""
                for line in lines[1:]:
                    if ": " in line:
                        k, v = line.split(": ", 1)
                        if k.lower() == "user-agent":
                            ua = v
                parts = req.split(" ")
                method = parts[0] if len(parts) >= 2 else "?"
                path = parts[1] if len(parts) >= 2 else "?"
                LOG.critical("🚨 CANARY HTTP: %s %s desde %s [UA: %s]", method, path, addr[0], ua[:60])
                self._alerts.disparar({"tipo": "canary_http", "componente": "canary_http",
                                        "detalle": f"{method} {path} desde {addr[0]} UA:{ua[:60]}",
                                        "severidad": "critica"})
                body = b"<html><body><h2>Console</h2><form method=POST action=/login><input name=user><input name=pass type=password><input type=submit></form></body></html>"
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
            except (socket.timeout, OSError):
                pass
            finally:
                conn.close()

    def iniciar(self):
        if self._activo:
            return
        self._activo = True

        def loop():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("0.0.0.0", self.puerto))
                s.listen(10)
                s.settimeout(1)
                LOG.info("🌐 Canary HTTP puerto %d", self.puerto)
                while self._activo:
                    try:
                        conn, addr = s.accept()
                        threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()
                    except socket.timeout:
                        continue
            except OSError as e:
                LOG.warning("Canary HTTP: %s", e)
            finally:
                s.close()

        threading.Thread(target=loop, daemon=True, name="CanaryHTTP").start()

    def detener(self):
        self._activo = False
