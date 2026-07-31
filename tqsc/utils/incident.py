"""
tqsc/utils/incident.py — NIST IR-4: Respuesta automatizada a incidentes.
Playbooks configurables que se ejecutan cuando se detecta un evento.
"""
import logging, json, time, subprocess, os
from pathlib import Path
from typing import Optional

LOG = logging.getLogger("tqsc.incident")


class Playbook:
    """Una respuesta automatizada a un tipo de incidente."""

    def __init__(self, nombre: str, disparador: str, acciones: list[str],
                 severidad_min: str = "HIGH", activo: bool = True):
        self.nombre = nombre
        self.disparador = disparador  # patrón en accion/recurso
        self.acciones = acciones
        self.severidad_min = severidad_min
        self.activo = activo
        self.ejecuciones: int = 0

    def coincide(self, evento: dict) -> bool:
        """True si este playbook debe ejecutarse para el evento."""
        if not self.activo:
            return False
        sev = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        if sev.get(evento.get("severidad", "INFO"), 0) < sev.get(self.severidad_min, 3):
            return False
        target = f"{evento.get('accion','')} {evento.get('recurso','')}".lower()
        return self.disparador.lower() in target

    def ejecutar(self, evento: dict) -> list[str]:
        """Ejecuta las acciones del playbook. Retorna resultados."""
        resultados = []
        for accion in self.acciones:
            try:
                if accion == "log_alert":
                    LOG.critical("INCIDENTE: %s | %s", self.nombre,
                                 json.dumps(evento, default=str))
                    resultados.append(f"log_alert: ok")
                elif accion == "block_ip":
                    ip = evento.get("detalle", "")
                    if ip:
                        LOG.warning("Playbook: bloqueando IP %s", ip)
                        from utils.firewall import FirewallManager
                        FirewallManager().bloquear_ip(ip, razon=f"Incidente: {self.nombre}")
                        resultados.append(f"block_ip: {ip}")
                elif accion == "notify_admin":
                    # TODO: This needs webhook/email integration
                    LOG.warning("Playbook: notificar admin — %s: %s",
                                self.nombre, evento.get("detalle", ""))
                    resultados.append("notify_admin: ok")
                elif accion.startswith("exec:"):
                    cmd = accion[5:].split()
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    resultados.append(f"exec: exit={r.returncode}")
                elif accion == "audit_export":
                    from utils.audit import obtener_audit
                    e = obtener_audit().estado()
                    resultados.append(f"audit: {e['entradas']} entradas")
                else:
                    resultados.append(f"{accion}: desconocida")
            except Exception as ex:
                resultados.append(f"{accion}: ERROR {ex}")
        self.ejecuciones += 1
        return resultados


class IncidentEngine:
    """Motor de respuesta a incidentes con playbooks registrables."""

    def __init__(self):
        self.playbooks: list[Playbook] = []
        self._cargar_defaults()

    def _cargar_defaults(self):
        """Playbooks por defecto."""
        defaults = [
            Playbook("login_fallido", "login", ["log_alert", "notify_admin"],
                     "HIGH", True),
            Playbook("mfa_fallido", "MFA", ["log_alert", "notify_admin", "block_ip"],
                     "CRITICAL", True),
            Playbook("sqli_detectado", "sqli", ["log_alert", "block_ip"],
                     "HIGH", True),
            Playbook("ataque_brute_force", "brute-force", ["log_alert", "block_ip"],
                     "HIGH", True),
            Playbook("auditoria_general", "admin", ["audit_export"],
                     "MEDIUM", False),
        ]
        self.playbooks.extend(defaults)

    def registrar(self, playbook: Playbook):
        self.playbooks.append(playbook)

    def procesar(self, evento: dict) -> list[dict]:
        """Procesa un evento contra todos los playbooks activos."""
        resultados = []
        for pb in self.playbooks:
            if pb.coincide(evento):
                res = pb.ejecutar(evento)
                resultados.append({"playbook": pb.nombre, "resultados": res})
        return resultados

    def estado(self) -> list[dict]:
        return [{"nombre": p.nombre, "disparador": p.disparador,
                 "activo": p.activo, "ejecuciones": p.ejecuciones}
                for p in self.playbooks]


_engine: Optional[IncidentEngine] = None


def obtener_engine() -> IncidentEngine:
    global _engine
    if _engine is None:
        _engine = IncidentEngine()
    return _engine
