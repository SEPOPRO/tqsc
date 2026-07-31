"""
tqsc/utils/sysmon_edr.py — Integración con Sysmon (driver kernel firmado por Microsoft).
Lee eventos del EventLog de Windows para obtener telemetría ring-0.
No requiere escribir kernel driver propio.

Sysmon Event IDs usados:
  1  = ProcessCreate       → ProcAnalyzer
  3  = NetworkConnect      → PacketWatch
  7  = ImageLoad           → PIDSignatureMatcher
  8  = CreateRemoteThread  → SyscallMonitor (inyección)
  11 = FileCreate          → FSMonitor
  13 = RegistryEvent       → RegistryMonitor
  15 = FileCreateStreamHash→ FSMonitor (alternate data streams)
"""
import logging, os, subprocess, json, threading, time, re
from collections import defaultdict
from typing import Optional
from xml.etree import ElementTree

LOG = logging.getLogger("tqsc.sysmon_edr")

SYSLOG_EVENT_IDS = {1, 3, 7, 8, 11, 13, 15}
EVENT_LABELS = {1: "ProcessCreate", 3: "NetworkConnect", 7: "ImageLoad",
                8: "CreateRemoteThread", 11: "FileCreate", 13: "RegistryEvent",
                15: "FileCreateStreamHash"}


class SysmonReader:
    """Lee eventos de Sysmon desde el EventLog de Windows.
    Usa wevtutil (no requiere pywin32).
    """

    def __init__(self, intervalo: int = 10, max_eventos: int = 100):
        self.intervalo = intervalo
        self.max_eventos = max_eventos
        self._ultimo_id: Optional[int] = None
        self._alertas: list[dict] = []
        self._activo = False
        self._hilo: Optional[threading.Thread] = None
        self._stats: dict[str, int] = defaultdict(int)

    def _sysmon_disponible(self) -> bool:
        """Verifica si Sysmon está instalado (driver presente)."""
        if os.name != "nt":
            return False
        try:
            r = subprocess.run(
                ["wevtutil", "get-log", "Microsoft-Windows-Sysmon/Operational"],
                capture_output=True, text=True, timeout=5, errors="replace")
            return r.returncode == 0
        except FileNotFoundError:
            return False

    def _ultimo_evento_id(self) -> int:
        """Obtiene el RecordID del último evento en el log Sysmon."""
        try:
            r = subprocess.run(
                ["wevtutil", "qe", "Microsoft-Windows-Sysmon/Operational",
                 "/q:", "*[System[(EventID=1)]]", "/c:1", "/rd:true",
                 "/e:Microsoft-Windows-Sysmon"],
                capture_output=True, text=True, timeout=5, errors="replace")
            if r.returncode != 0 or not r.stdout.strip():
                return 0
            xml_data = f"<Events>{r.stdout}</Events>"
            root = ElementTree.fromstring(xml_data)
            ns = {"sys": "http://schemas.microsoft.com/win/2004/08/events/event"}
            sys_elem = root.find(".//sys:System", ns)
            if sys_elem is not None:
                rid = sys_elem.find("sys:EventRecordID", ns)
                if rid is not None and rid.text:
                    return int(rid.text)
            return 0
        except Exception:
            return 0

    def leer_eventos(self, desde_id: int = 0) -> list[dict]:
        """Lee eventos Sysmon desde un RecordID específico."""
        eventos = []
        try:
            # Query estructurada con XPath
            query = f"*[System[(EventRecordID > {desde_id})]]"
            r = subprocess.run(
                ["wevtutil", "qe", "Microsoft-Windows-Sysmon/Operational",
                 "/q:", query, "/c:", str(self.max_eventos),
                 "/e:Microsoft-Windows-Sysmon"],
                capture_output=True, text=True, timeout=10, errors="replace")
            if r.returncode != 0 or not r.stdout.strip():
                return eventos

            # Parsear XML
            xml_data = f"<Events>{r.stdout}</Events>"
            root = ElementTree.fromstring(xml_data)
            ns = {"sys": "http://schemas.microsoft.com/win/2004/08/events/event",
                  "e": "http://schemas.microsoft.com/win/2004/08/events/event"}
            for event_elem in root.findall(".//sys:System/..", ns):
                if event_elem is None:
                    continue
                parsed = self._parse_evento(event_elem)
                if parsed:
                    eventos.append(parsed)
        except Exception as e:
            LOG.debug("SysmonReader: error leyendo eventos: %s", e)
        return eventos

    def _parse_evento(self, xml_elem) -> Optional[dict]:
        """Parsea un evento Sysmon XML a formato TQSC."""
        try:
            ns = {"sys": "http://schemas.microsoft.com/win/2004/08/events/event",
                  "e": "http://schemas.microsoft.com/win/2004/08/events/event"}

            # System info
            sys_node = xml_elem.find(".//sys:System", ns)
            if sys_node is None:
                return None
            event_id = int(sys_node.findtext("sys:EventID", "0", ns))
            record_id = int(sys_node.findtext("sys:EventRecordID", "0", ns))

            if event_id not in SYSLOG_EVENT_IDS:
                return None

            # Data nodes
            data = {}
            for d in xml_elem.findall(".//sys:EventData/sys:Data", ns):
                name = d.get("Name", "")
                if name:
                    data[name] = d.text or ""

            # Mapear a alerta TQSC
            alerta = self._mapear(event_id, data, record_id)
            if alerta:
                self._stats[EVENT_LABELS.get(event_id, f"ID_{event_id}")] += 1
            return alerta
        except Exception as e:
            LOG.debug("SysmonReader: error parseando evento: %s", e)
            return None

    def _mapear(self, event_id: int, data: dict, record_id: int) -> Optional[dict]:
        """Mapea evento Sysmon a alerta TQSC."""
        base = {"fuente": "sysmon", "record_id": record_id, "ts": time.time()}

        if event_id == 1:  # ProcessCreate
            return {**base, "tipo": "proceso", "accion": "creado",
                    "detalle": f"{data.get('Image','')} / PID {data.get('ProcessId','')}"
                               f" / PPID {data.get('ParentProcessId','')}"
                               f" / CmdLine: {data.get('CommandLine','')[:200]}",
                    "severidad": "info"}
        elif event_id == 3:  # NetworkConnect
            dest_ip = data.get("DestinationIp", "?")
            dest_port = data.get("DestinationPort", "?")
            proto = data.get("Protocol", "?")
            sev = "warn"
            if dest_port in ("3389", "445", "23", "135", "139"):
                sev = "crit"
            elif dest_port in ("4444", "6666", "6667", "6668", "6669", "31337"):
                sev = "crit"
            return {**base, "tipo": "red", "accion": "conexion",
                    "detalle": f"{data.get('Image','')} → {dest_ip}:{dest_port} ({proto})",
                    "severidad": sev}
        elif event_id == 7:  # ImageLoad
            return {**base, "tipo": "imagen", "accion": "cargada",
                    "detalle": f"{data.get('Image','')} cargó {data.get('ImageLoaded','')}",
                    "severidad": "info"}
        elif event_id == 8:  # CreateRemoteThread
            return {**base, "tipo": "inyeccion", "accion": "thread_remoto",
                    "detalle": f"PID {data.get('SourceProcessId','')} → PID {data.get('TargetProcessId','')}"
                               f" ({data.get('StartModule','')})",
                    "severidad": "crit"}
        elif event_id == 11:  # FileCreate
            return {**base, "tipo": "archivo", "accion": "creado",
                    "detalle": f"{data.get('Image','')} creó {data.get('TargetFilename','')}",
                    "severidad": "info"}
        elif event_id == 13:  # RegistryEvent
            return {**base, "tipo": "registro", "accion": "modificado",
                    "detalle": f"{data.get('Image','')} → {data.get('TargetObject','')[:200]}",
                    "severidad": "warn"}
        elif event_id == 15:  # FileCreateStreamHash
            return {**base, "tipo": "archivo", "accion": "ads_creado",
                    "detalle": f"{data.get('Image','')} → {data.get('TargetFilename','')}"
                               f":{data.get('StreamHash','')}",
                    "severidad": "warn"}
        return None

    def escanear(self) -> list[dict]:
        """Escanea eventos Sysmon nuevos desde el último check."""
        if os.name != "nt":
            return []
        eventos = self.leer_eventos(self._ultimo_id or 0)
        for e in eventos:
            rid = e.get("record_id", 0)
            if rid > (self._ultimo_id or 0):
                self._ultimo_id = rid
            self._alertas.append(e)
        # Podar historial
        if len(self._alertas) > 5000:
            self._alertas = self._alertas[-2000:]
        return eventos

    def iniciar(self):
        if self._activo:
            return
        if not self._sysmon_disponible():
            LOG.warning("Sysmon no instalado — EDR ring-0 no disponible. "
                        "Instale Sysmon: https://learn.microsoft.com/sysinternals/downloads/sysmon")
            return
        self._ultimo_id = self._ultimo_evento_id()
        self._activo = True
        def _loop():
            while self._activo:
                try:
                    self.escanear()
                except Exception as e:
                    LOG.error("SysmonReader: %s", e)
                time.sleep(self.intervalo)
        self._hilo = threading.Thread(target=_loop, daemon=True, name="SysmonReader")
        self._hilo.start()
        LOG.info("SysmonReader activo (eventos desde ID %d)", self._ultimo_id)

    def detener(self):
        self._activo = False

    def estado(self) -> dict:
        return {"activo": self._activo,
                "ultimo_id": self._ultimo_id,
                "alertas": len(self._alertas),
                "stats": dict(self._stats),
                "sysmon_instalado": self._sysmon_disponible()}


_reader: Optional[SysmonReader] = None
def obtener_sysmon() -> SysmonReader:
    global _reader
    if _reader is None:
        _reader = SysmonReader()
    return _reader
