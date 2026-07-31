"""
tqsc/deception/mtd.py — Moving Target Defense con netsh/iptables real.
"""
import logging, subprocess, secrets, threading, time, os
from typing import Optional

LOG = logging.getLogger("tqsc.deception.mtd")
ES_WINDOWS = os.name == "nt"


class MovingTargetDefense:
    """Rotación de puertos mediante reglas de firewall reales."""

    def __init__(self, intervalo: int = 300):
        self.intervalo = intervalo
        self._servicios: dict[str, int] = {}
        self._rebind_callbacks = {}
        self._activo = False

    def registrar_rebind(self, servicio: str, callback):
        self._rebind_callbacks[servicio] = callback

    def _ejecutar(self, cmd: list[str]) -> bool:
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=10)
            return r.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def rotar(self, servicio: str) -> int:
        viejo = self._servicios.get(servicio, 0)
        nuevo = secrets.randbelow(50000) + 1024
        while nuevo == viejo:
            nuevo = secrets.randbelow(50000) + 1024

        if ES_WINDOWS and viejo:
            self._ejecutar(["netsh", "advfirewall", "firewall", "delete", "rule", f"name=TQSC_MTD_{servicio}"])
        if ES_WINDOWS:
            ok = self._ejecutar(["netsh", "advfirewall", "firewall", "add", "rule", f"name=TQSC_MTD_{servicio}",
                                 "dir=in", "action=allow", "protocol=tcp", f"localport={nuevo}", "enable=yes"])
        else:
            ok = self._ejecutar(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(nuevo), "-j", "ACCEPT"])
            if viejo:
                self._ejecutar(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(viejo), "-j", "ACCEPT"])
        if ok:
            self._servicios[servicio] = nuevo
            LOG.info("🔄 MTD: %s %d -> %d", servicio, viejo, nuevo)
            LOG.warning("MTD rotó el puerto de firewall para %s, pero la app sigue en el anterior", servicio)
            # TODO: Invocar self._rebind_callbacks[servicio](nuevo) para rebindear el socket
        return nuevo

    def iniciar(self):
        if self._activo:
            return
        self._activo = True
        for svc in ["honeypot_ssh", "api_gateway", "admin_panel"]:
            self.rotar(svc)

        def loop():
            while self._activo:
                time.sleep(self.intervalo)
                for svc in list(self._servicios.keys()):
                    self.rotar(svc)

        threading.Thread(target=loop, daemon=True, name="MTD").start()
        LOG.info("🔄 MTD activo (rotacion cada %ds)", self.intervalo)

    def detener(self):
        self._activo = False
        for svc, puerto in list(self._servicios.items()):
            if ES_WINDOWS:
                self._ejecutar(["netsh", "advfirewall", "firewall", "delete", "rule", f"name=TQSC_MTD_{svc}"])
            else:
                self._ejecutar(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(puerto), "-j", "ACCEPT"])
        self._servicios.clear()

    def estado(self) -> dict:
        return {"servicios": dict(self._servicios)}
