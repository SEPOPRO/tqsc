"""
tqsc/deception/canary_dns.py — Servidor DNS UDP real para canary tokens.
"""
import logging, socket, struct, threading, time, secrets
from typing import Optional
from .alert_engine import AlertEngine

LOG = logging.getLogger("tqsc.deception.canary_dns")


class CanaryDNS:
    """Servidor DNS UDP que logea consultas a subdominios canary."""

    def __init__(self, alerts: AlertEngine, puerto: int = 5353, dominio: str = "canary.tqsc.internal"):
        self._alerts = alerts
        self.puerto = puerto
        self.dominio = dominio
        self._tokens: dict[str, dict] = {}
        self._activo = False
        self._sock: Optional[socket.socket] = None

    def generar(self, memo: str = "") -> str:
        sub = f"{secrets.token_hex(8)}.{self.dominio}"
        self._tokens[sub] = {"memo": memo, "disparado": False}
        return sub

    def _handle_query(self, data: bytes, addr: tuple):
        try:
            labels = []
            i = 12
            while i < len(data):
                l = data[i]
                if l == 0:
                    break
                i += 1
                labels.append(data[i:i + l].decode("ascii", errors="replace").lower())
                i += l
            fqdn = ".".join(labels)
            if fqdn in self._tokens and not self._tokens[fqdn]["disparado"]:
                self._tokens[fqdn]["disparado"] = True
                self._alerts.disparar({"tipo": "canary_dns", "componente": "canary_dns",
                                        "detalle": f"{fqdn} desde {addr[0]}", "severidad": "critica"})
                LOG.critical("🚨 CANARY DNS: %s desde %s", fqdn, addr[0])
        except Exception as e:
            LOG.debug("DNS parse error: %s", e)

    def verificar(self, dominio: str) -> bool:
        if dominio in self._tokens and not self._tokens[dominio]["disparado"]:
            self._tokens[dominio]["disparado"] = True
            self._alerts.disparar({"tipo": "canary_dns", "componente": "canary_dns",
                                    "detalle": f"{dominio} (offline)", "severidad": "critica"})
            return True
        return False

    def iniciar(self):
        if self._activo:
            return
        self._activo = True

        def loop():
            try:
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._sock.bind(("0.0.0.0", self.puerto))
                self._sock.settimeout(1)
                LOG.info("🌐 Canary DNS UDP %d", self.puerto)
                while self._activo:
                    try:
                        data, addr = self._sock.recvfrom(512)
                        self._handle_query(data, addr)
                        tid = data[:2]
                        resp = tid + struct.pack(">H", 0x8183) + data[4:6] + struct.pack(">HHH", 0, 0, 0) + data[12:]
                        self._sock.sendto(resp, addr)
                    except socket.timeout:
                        continue
            except OSError as e:
                LOG.warning("Canary DNS: %s", e)

        threading.Thread(target=loop, daemon=True, name="CanaryDNS").start()

    def detener(self):
        self._activo = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
