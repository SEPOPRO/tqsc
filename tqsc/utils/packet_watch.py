"""
tqsc/utils/packet_watch.py — Monitoreo de conexiones de red en tiempo real.
Detecta: escaneo de puertos, conexiones sospechosas, DNS anómalo.
Sin dependencias externas (psutil + socket + stdlib).
"""
import logging, os, time, threading, socket, struct
from collections import defaultdict
from typing import Optional
from ipaddress import ip_address

LOG = logging.getLogger("tqsc.packet_watch")

# Puertos conocidos para servicios legítimos
PUERTOS_CONOCIDOS = {22, 25, 53, 80, 443, 465, 587, 993, 995, 8080, 8443,
                     9090, 3306, 5432, 6379, 27017}
PUERTOS_SOSPECHOSOS = {23, 135, 139, 445, 1433, 1521, 3389, 5900, 5901,
                       6666, 6667, 6668, 6669, 31337}
RANGOS_PRIVADOS = ["10.", "172.16.", "172.17.", "172.18.", "172.19.",
                   "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                   "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                   "172.30.", "172.31.", "192.168.", "127.", "0."]


class DNSQuery:
    """Monitoreo de consultas DNS a nivel de sistema."""
    def __init__(self):
        self._consultas: dict[str, list[float]] = defaultdict(list)
        self._dominios_bloqueados: set[str] = set()

    def registrar(self, dominio: str):
        ahora = time.time()
        self._consultas[dominio].append(ahora)
        podar = [t for t in self._consultas[dominio] if ahora - t < 3600]
        self._consultas[dominio] = podar

    def es_sospechoso(self, dominio: str) -> bool:
        # Domain Generation Algorithm (DGA) heuristic
        dominio = dominio.lower().rstrip(".")
        if dominio in self._dominios_bloqueados:
            return True
        # Alto ratio de consonantes en subdominio
        partes = dominio.split(".")
        if len(partes) >= 2:
            sub = partes[0]
            if len(sub) >= 8:
                consonantes = sum(1 for c in sub if c not in "aeiou")
                if consonantes / len(sub) > 0.7:
                    return True
        # Dominio muy largo
        if len(dominio) > 50:
            return True
        # Tunneling DNS (consultas muy frecuentes al mismo dominio)
        ahora = time.time()
        recientes = [t for t in self._consultas[dominio] if ahora - t < 60]
        if len(recientes) > 60:
            return True
        return False

    def bloquear(self, dominio: str):
        self._dominios_bloqueados.add(dominio.lower())

    def estado(self) -> dict:
        return {"consultas_activas": sum(len(v) for v in self._consultas.values()),
                "bloqueados": len(self._dominios_bloqueados)}


class PortScanDetector:
    """Detecta escaneo de puertos por IP origen."""

    def __init__(self, umbral: int = 20, ventana: int = 10):
        self.umbral = umbral
        self.ventana = ventana
        self._conexiones: dict[str, list[tuple[float, int]]] = defaultdict(list)

    def registrar(self, ip: str, puerto: int):
        ahora = time.time()
        self._conexiones[ip].append((ahora, puerto))
        # Podar viejas
        self._conexiones[ip] = [(t, p) for t, p in self._conexiones[ip]
                                 if ahora - t < self.ventana]

    def es_escaneo(self, ip: str) -> bool:
        conexiones = self._conexiones.get(ip, [])
        ahora = time.time()
        recientes = [(t, p) for t, p in conexiones if ahora - t < self.ventana]
        # Múltiples puertos distintos en ventana corta
        puertos_distintos = len(set(p for _, p in recientes))
        if puertos_distintos >= self.umbral:
            return True
        # Puertos sospechosos consecutivos
        sospechosos = sum(1 for _, p in recientes if p in PUERTOS_SOSPECHOSOS)
        if sospechosos >= 5:
            return True
        return False

    def alertas(self) -> list[dict]:
        return [{"ip": ip, "puertos": len(set(p for _, p in conns))}
                for ip, conns in self._conexiones.items()
                if self.es_escaneo(ip)]


class PacketWatch:
    """Monitor de conexiones de red: establecidas, origen, destino, anomalías."""

    def __init__(self, intervalo: int = 10):
        self.intervalo = intervalo
        self.psd = PortScanDetector()
        self.dns = DNSQuery()
        self._conexiones_previas: set = set()
        self._alertas: list[dict] = []
        self._activo = False
        self._hilo: Optional[threading.Thread] = None

    def escanear(self) -> list[dict]:
        """Escanea conexiones de red activas y detecta anomalías."""
        alertas = []
        try:
            import psutil
            conns = psutil.net_connections(kind="inet")
            actuales = set()
            for c in conns:
                if c.status != "ESTABLISHED":
                    continue
                if not c.raddr:
                    continue
                ip = c.raddr.ip
                puerto = c.raddr.port
                pid = c.pid or 0
                key = (ip, puerto, pid)
                actuales.add(key)

                # Registrar para detección de escaneo
                self.psd.registrar(ip, puerto)

                # Detectar conexiones a puertos sospechosos
                if puerto in PUERTOS_SOSPECHOSOS:
                    alertas.append({"t": "red", "n": "packet_watch",
                                    "a": f"puerto_sospechoso:{puerto}",
                                    "d": f"{ip}:{puerto} (PID {pid})",
                                    "s": "warn"})
                # Detectar conexiones externas a servicios internos
                if puerto < 1024 and not any(ip.startswith(p) for p in RANGOS_PRIVADOS):
                    alertas.append({"t": "red", "n": "packet_watch",
                                    "a": "servicio_expuesto",
                                    "d": f"{ip}:{puerto} (PID {pid})",
                                    "s": "crit"})

            # Detectar conexiones nuevas
            nuevas = actuales - self._conexiones_previas
            if len(nuevas) > 50:
                alertas.append({"t": "red", "n": "packet_watch",
                                "a": "explosion_conexiones",
                                "d": f"{len(nuevas)} nuevas conexiones",
                                "s": "crit"})
            self._conexiones_previas = actuales

        except (ImportError, PermissionError, OSError) as e:
            if "psutil" not in str(e):
                alertas.append({"t": "red", "n": "packet_watch",
                                "a": "error", "d": str(e), "s": "warn"})

        # Alertas de port scan
        for a in self.psd.alertas():
            alertas.append({"t": "red", "n": "port_scan",
                            "a": "escaneo_puertos",
                            "d": f"{a['ip']} → {a['puertos']} puertos",
                            "s": "crit"})

        self._alertas.extend(alertas)
        if len(self._alertas) > 1000:
            self._alertas = self._alertas[-500:]
        return alertas

    def iniciar(self):
        if self._activo:
            return
        self._activo = True
        def _loop():
            while self._activo:
                try:
                    self.escanear()
                except Exception as e:
                    LOG.error("PacketWatch: %s", e)
                time.sleep(self.intervalo)
        self._hilo = threading.Thread(target=_loop, daemon=True, name="PacketWatch")
        self._hilo.start()
        LOG.info("PacketWatch activo (intervalo=%ds)", self.intervalo)

    def detener(self):
        self._activo = False

    def estado(self) -> dict:
        return {"alertas": len(self._alertas),
                "conexiones_activas": len(self._conexiones_previas),
                "dns_consultas": self.dns.estado()["consultas_activas"]}


_watch: Optional[PacketWatch] = None
def obtener_watch() -> PacketWatch:
    global _watch
    if _watch is None:
        _watch = PacketWatch()
    return _watch
