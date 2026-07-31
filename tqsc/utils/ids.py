"""
tqsc/utils/ids.py — Sistema de detección de intrusiones ligero.
Correlación de conexiones + patrones de ataque + respuestas automáticas.
"""
import logging, time, threading
from collections import defaultdict
from typing import Optional

LOG = logging.getLogger("tqsc.ids")

# Firmas de ataque básicas
FIRMAS = {
    "port_scan": {"patron": "múltiples puertos", "severidad": "HIGH"},
    "dns_tunnel": {"patron": "consultas DNS frecuentes", "severidad": "MEDIUM"},
    "brute_force_red": {"patron": "múltiples conexiones mismo origen", "severidad": "HIGH"},
    "data_exfil": {"patron": "conexiones salientes a IPs desconocidas", "severidad": "CRITICAL"},
    "service_expose": {"patron": "servicio interno expuesto", "severidad": "HIGH"},
}


class IDSEngine:
    """Motor IDS: analiza eventos de red y ejecuta respuestas."""

    def __init__(self):
        self._eventos: list[dict] = []
        self._alertas: list[dict] = []
        self._limite_por_ip: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def analizar(self, eventos: list[dict]) -> list[dict]:
        """Analiza eventos de red y detecta patrones de ataque."""
        alertas = []
        ahora = time.time()
        with self._lock:
            self._eventos.extend(eventos)
            if len(self._eventos) > 10000:
                self._eventos = self._eventos[-5000:]

        # Agrupar por IP origen
        for e in eventos:
            ip = None
            detalle = e.get("d", "")
            # Extraer IP del detalle (formato: "ip:puerto")
            if ":" in detalle:
                ip = detalle.split(":")[0].strip()
            if not ip:
                continue

            self._limite_por_ip[ip].append(ahora)
            self._limite_por_ip[ip] = [t for t in self._limite_por_ip[ip]
                                         if ahora - t < 60]

            # Brute force: >20 conexiones/min desde misma IP
            if len(self._limite_por_ip[ip]) > 20:
                alertas.append({
                    "t": "ids", "n": "ids_engine", "a": "brute_force_red",
                    "d": f"{ip}: {len(self._limite_por_ip[ip])} conexiones/min",
                    "s": "crit"
                })
                self._limite_por_ip[ip] = []  # Resetear para no alarma repetida

        # Detectar data exfiltration: muchas conexiones salientes
        salientes = [e for e in self._eventos[-100:] if "out" in e.get("d", "").lower()]
        if len(salientes) > 30:
            alertas.append({
                "t": "ids", "n": "ids_engine", "a": "data_exfil",
                "d": f"{len(salientes)} conexiones salientes en últimos eventos",
                "s": "crit"
            })

        with self._lock:
            self._alertas.extend(alertas)
            if len(self._alertas) > 1000:
                self._alertas = self._alertas[-500:]

        return alertas

    def recomendar_respuesta(self, alerta: dict) -> str:
        """Recomienda acción según el tipo de alerta."""
        accion = alerta.get("a", "")
        if "brute_force" in accion:
            return "bloquear_ip"
        if "port_scan" in accion or "escaneo" in accion:
            return "bloquear_ip"
        if "data_exfil" in accion:
            return "bloquear_ip"
        if "dns_tunnel" in accion or "dns" in accion:
            return "monitorear"
        if "service" in accion:
            return "notificar"
        return "monitorear"

    def estado(self) -> dict:
        return {"eventos_analizados": len(self._eventos),
                "alertas_generadas": len(self._alertas),
                "firmas": len(FIRMAS),
                "ips_monitoreadas": len(self._limite_por_ip)}


_ids: Optional[IDSEngine] = None
def obtener_ids() -> IDSEngine:
    global _ids
    if _ids is None:
        _ids = IDSEngine()
    return _ids
