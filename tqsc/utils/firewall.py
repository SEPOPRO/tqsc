"""
tqsc/utils/firewall.py — Gestión programática de firewall.
Windows: netsh advfirewall
Linux: iptables/nftables
Bloqueo/desbloqueo de IPs, puertos, aplicaciones.
"""
import logging, os, subprocess, threading, time
from typing import Optional

LOG = logging.getLogger("tqsc.firewall")

# Reglas de firewall predefinidas por nivel de amenaza
REGLA_BASICA = {"accion": "block", "dir": "in", "protocolo": "tcp"}
REGLA_ESTRICTA = {"accion": "block", "dir": "both", "protocolo": "any"}


class FirewallManager:
    """Gestión de firewall cross-platform."""

    def __init__(self):
        self._reglas_activas: list[dict] = []
        self._es_windows = os.name == "nt"
        self._historial: list[dict] = []
        self._lock = threading.Lock()

    def _ejecutar(self, cmd: list[str]) -> tuple[bool, str]:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            ok = r.returncode == 0
            return ok, r.stdout + r.stderr
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return False, str(e)

    def bloquear_ip(self, ip: str, razon: str = "") -> bool:
        """Bloquea una IP entrante/saliente."""
        regla = {"ip": ip, "razon": razon, "timestamp": time.time(), "activa": True}
        ok = False
        if self._es_windows:
            ok, _ = self._ejecutar([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=TQSC_Block_{ip}", f"dir=in", "action=block",
                f"remoteip={ip}", "enable=yes"
            ])
            if ok:
                ok2, _ = self._ejecutar([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=TQSC_Block_{ip}_out", f"dir=out", "action=block",
                    f"remoteip={ip}", "enable=yes"
                ])
                ok = ok and ok2
        else:
            ok, _ = self._ejecutar([
                "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"
            ])
        if ok:
            with self._lock:
                self._reglas_activas.append(regla)
                self._historial.append({"accion": "bloquear", "ip": ip, "razon": razon, "ok": True})
            LOG.warning("Firewall: IP bloqueada %s (%s)", ip, razon)
        else:
            LOG.warning("Firewall: no se pudo bloquear %s (sin permisos)", ip)
        return ok

    def desbloquear_ip(self, ip: str) -> bool:
        """Desbloquea una IP."""
        ok = False
        if self._es_windows:
            ok, _ = self._ejecutar([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name=TQSC_Block_{ip}"
            ])
            self._ejecutar([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name=TQSC_Block_{ip}_out"
            ])
        else:
            ok, _ = self._ejecutar(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
        with self._lock:
            self._reglas_activas = [r for r in self._reglas_activas if r.get("ip") != ip]
            self._historial.append({"accion": "desbloquear", "ip": ip, "ok": ok})
        if ok:
            LOG.info("Firewall: IP desbloqueada %s", ip)
        return ok

    def bloquear_puerto(self, puerto: int, protocolo: str = "tcp") -> bool:
        """Bloquea un puerto específico."""
        ok = False
        if self._es_windows:
            ok, _ = self._ejecutar([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=TQSC_Block_Port_{puerto}", f"dir=in", "action=block",
                f"protocol={protocolo}", f"localport={puerto}", "enable=yes"
            ])
        else:
            ok, _ = self._ejecutar([
                "iptables", "-A", "INPUT", "-p", protocolo,
                "--dport", str(puerto), "-j", "DROP"
            ])
        if ok:
            with self._lock:
                self._historial.append({"accion": "bloquear_puerto", "puerto": puerto, "ok": True})
            LOG.warning("Firewall: puerto %d/%s bloqueado", puerto, protocolo)
        return ok

    def listar_reglas(self) -> list[dict]:
        """Lista reglas activas gestionadas por TQSC."""
        return list(self._reglas_activas)

    def limpiar(self):
        """Elimina todas las reglas creadas por TQSC."""
        with self._lock:
            for r in list(self._reglas_activas):
                self.desbloquear_ip(r["ip"])
            self._reglas_activas.clear()
            self._historial.append({"accion": "limpiar", "ok": True})

    def estado(self) -> dict:
        return {"reglas_activas": len(self._reglas_activas),
                "historial": len(self._historial),
                "soporte_firewall": self._es_windows or os.path.exists("/sbin/iptables")}


_fw: Optional[FirewallManager] = None
def obtener_firewall() -> FirewallManager:
    global _fw
    if _fw is None:
        _fw = FirewallManager()
    return _fw
