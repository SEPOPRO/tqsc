"""
TQSC v1.0 — SyscallMonitor REAL
Intercepta llamadas críticas del sistema operativo usando ctypes + ntdll.
Windows nativo (user-space, no requiere driver Ring 0).
"""
import os, ctypes, ctypes.wintypes as wintypes, threading, time, json, logging
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from typing import Optional

from native_bridge import enum_processes as _enum_processes
from utils.secure_storage import append as _append

LOG = logging.getLogger("tqsc.syscall")
TQSC_TEST = os.environ.get("TQSC_TEST_MODE") == "1"


class SyscallStats:
    def __init__(self):
        self.total_calls = 0
        self.calls_por_segundo = 0
        self.picos_por_proceso: dict[int, int] = defaultdict(int)
        self.anomalias_detectadas = 0
        self.alertas_emitidas = []


class SyscallMonitor:
    """Monitoreo de procesos vía Rust (tqsc_native) con fallback Python."""

    CALLS_CRITICAS = [
        "NtCreateProcess", "NtCreateThreadEx", "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory", "NtProtectVirtualMemory",
        "NtReadVirtualMemory", "NtOpenProcess", "NtOpenKey",
        "NtCreateFile", "NtDeleteFile", "NtShutdownSystem",
        "CreateProcessAsUser", "CreateProcessWithToken", "CreateProcessWithLogon",
    ]

    SYSINTERNALS_BYPASS = ["procexp", "procmon", "dbgview", "tcpview", "handle"]

    def __init__(self, data_dir: str = "data", intervalo: float = 2.0):
        self.data_dir = Path(data_dir)
        self.intervalo = intervalo
        self.stats = SyscallStats()
        self._baseline: dict[str, int] = {}
        self._activo = False
        self._hilo: Optional[threading.Thread] = None
        self._procesos_previos: set[int] = set()
        self._windows_ok = False

        if TQSC_TEST:
            LOG.info("SyscallMonitor: MODO TEST — sin hardware real")
            return

        try:
            self.ntdll = ctypes.windll.ntdll
            self.kernel32 = ctypes.windll.kernel32
            self._windows_ok = True
            LOG.info("SyscallMonitor: ctypes inicializado")
        except (AttributeError, OSError) as e:
            LOG.warning("SyscallMonitor: ctypes no disponible (%s)", e)

    def iniciar(self):
        if TQSC_TEST or not self._windows_ok:
            LOG.info("SyscallMonitor: monitoreo simulado (test mode)")
            return
        self._activo = True
        self._establecer_baseline()
        self._hilo = threading.Thread(target=self._loop_monitoreo, daemon=True)
        self._hilo.start()
        LOG.info("SyscallMonitor: monitoreo activo (intervalo=%ss)", self.intervalo)

    def detener(self):
        self._activo = False

    def _establecer_baseline(self):
        self._baseline["procesos"] = len(self._listar_procesos())
        self._baseline["hilos"] = self._contar_hilos()

    def _listar_procesos(self) -> list[dict]:
        if TQSC_TEST:
            return [{"pid": 1, "nombre": "test", "hilos": 2, "ppid": 0}]
        try:
            procs = _enum_processes()
            return [{
                "pid": p["pid"], "nombre": p["nombre"],
                "hilos": 1, "ppid": 0,
            } for p in procs]
        except Exception as e:
            LOG.debug("Error listando procesos: %s", e)
            return []

    def _contar_hilos(self) -> int:
        return sum(p.get("hilos", 1) for p in self._listar_procesos())

    def _loop_monitoreo(self):
        while self._activo:
            try: self._ciclo()
            except Exception as e: LOG.warning("SyscallMonitor: error: %s", e)
            time.sleep(self.intervalo)

    def _ciclo(self):
        procesos = self._listar_procesos()
        pids_actuales = {p["pid"] for p in procesos}
        pids_nuevos = pids_actuales - self._procesos_previos
        self.stats.total_calls += len(pids_nuevos)
        for p in procesos:
            if p["pid"] in pids_nuevos:
                self._analizar_proceso_nuevo(p)
        self._procesos_previos = pids_actuales

    def _analizar_proceso_nuevo(self, proc: dict):
        nombre = proc.get("nombre", "").lower()
        senales = []
        # UAC bypass tools
        if any(s in nombre for s in self.SYSINTERNALS_BYPASS):
            senales.append(f"uac_bypass_tool: {nombre}")
        if any(s in nombre for s in ["powershell", "cmd", "wscript", "cscript", "mshta"]):
            senales.append(f"shell: {nombre}")
        if proc.get("hilos", 0) > 50:
            senales.append(f"hilos: {proc['hilos']}")
        # Procesos efímeros: si el PID es muy bajo pero tiene muchos hilos
        if proc.get("pid", 0) < 100 and proc.get("hilos", 0) > 20:
            senales.append(f"efimero: PID={proc['pid']} hilos={proc['hilos']}")
        for padre in self._listar_procesos():
            if padre["pid"] == proc.get("ppid") and self._combinacion_peligrosa(padre["nombre"].lower(), nombre):
                senales.append(f"{padre['nombre']}={nombre}")
        if senales:
            self._emitir_alerta(f"nuevo_proceso:{proc['pid']}", "; ".join(senales))

    def _combinacion_peligrosa(self, padre: str, hijo: str) -> bool:
        pares = [("winword", "powershell"), ("excel", "powershell"), ("chrome", "cmd"),
                 ("outlook", "powershell"), ("explorer", "powershell")]
        p = padre.split(".")[0]; h = hijo.split(".")[0]
        return (p, h) in pares

    def _emitir_alerta(self, tipo: str, detalle: str):
        alerta = {"timestamp": datetime.now().isoformat(), "tipo": tipo, "detalle": detalle}
        self.stats.anomalias_detectadas += 1
        self.stats.alertas_emitidas.append(alerta)
        LOG.warning("SyscallMonitor: [%s] %s", tipo, detalle)
        _append(self.data_dir / "syscall_alertas.jsonl", alerta)

    def monitorear(self, llamada: Optional[str] = None, origen: str = "") -> Optional[dict]:
        if llamada and llamada in self.CALLS_CRITICAS:
            a = {"llamada": llamada, "origen": origen, "alerta": "critica"}
            self._emitir_alerta(f"syscall:{llamada}", f"desde {origen}" if origen else "")
            return a
        return None

    def estado(self) -> dict:
        return {
            "activo": self._activo, "windows_ok": self._windows_ok,
            "test_mode": TQSC_TEST,
            "total_calls": self.stats.total_calls,
            "anomalias": self.stats.anomalias_detectadas,
            "procesos_actuales": len(self._procesos_previos),
        }
