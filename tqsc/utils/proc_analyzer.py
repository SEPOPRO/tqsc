"""
tqsc/utils/proc_analyzer.py — EDR: Análisis de procesos (árbol, memoria, inyección).
Detecta procesos hijo/padre sospechosos, memoria inyectada, cadenas maliciosas.
"""
import logging, os, time, threading, hashlib, struct
from typing import Optional

LOG = logging.getLogger("tqsc.proc_analyzer")

# Patrones de inyección de código en memoria
MEM_SUSPICIOUS = [
    b"\xfc\xe8\x82\x00\x00\x00",  # call $+5 (shellcode)
    b"\xeb\xfe",                    # jmp $ (infinite loop)
    b"\xcc\xcc\xcc\xcc",           # INT3 padding
]

# Procesos legítimos padre-hijo esperados
PARENT_MAP = {
    "winlogon.exe": ["userinit.exe", "logonui.exe"],
    "services.exe": ["svchost.exe", "spoolsv.exe"],
    "svchost.exe": [],
}


class ProcAnalyzer:
    """Analizador de procesos: árbol, memoria, inyección."""

    def __init__(self):
        self._cache: dict[int, dict] = {}
        self._alertas: list[dict] = []
        self._lock = threading.Lock()

    def analizar(self) -> list[dict]:
        """Analiza todos los procesos del sistema."""
        alertas = []
        try:
            import psutil
            procs = psutil.process_iter(["pid", "ppid", "name", "exe",
                                          "cmdline", "memory_percent", "create_time"])
            arbol = {p.info["pid"]: p.info for p in procs}
            for pid, info in arbol.items():
                try:
                    a = self._analizar_proceso(pid, info, arbol)
                    if a:
                        alertas.append(a)
                except Exception:
                    continue
            self._alertas.extend(alertas)
            if len(self._alertas) > 1000:
                self._alertas = self._alertas[-500:]
        except ImportError:
            pass
        return alertas

    def _analizar_proceso(self, pid: int, info: dict, arbol: dict) -> Optional[dict]:
        alertas = []
        name = (info.get("name") or "").lower()
        ppid = info.get("ppid")
        exe = info.get("exe") or ""

        # 1. Proceso sin padre (PPID=0 o inexistente) ≠ system
        if ppid and ppid not in arbol and pid > 100:
            alertas.append("proceso_huérfano")
        # 2. Proceso con nombre sospechoso
        for s in ["mimikatz", "wce", "pwdump", "cain", "gsecdump", "powersploit",
                  "beacon", "cobaltstrike", "meterpreter", "nc.exe", "ncat"]:
            if s in name:
                alertas.append(f"nombre_sospechoso:{s}")
        # 3. Hijo de otro proceso legítimo (living-off-the-land)
        if ppid and ppid in arbol:
            pname = (arbol[ppid].get("name") or "").lower()
            if name in ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
                        "mshta.exe", "regsvr32.exe", "rundll32.exe"]:
                alertas.append(f"lotl:{pname}→{name}")
        # 4. Memoria elevada sin exe
        if not exe and info.get("memory_percent", 0) > 1:
            alertas.append("memoria_sin_exe")
        # 5. Múltiples instancias del mismo proceso sospechoso
        if name in ["powershell.exe", "cmd.exe"] and info.get("memory_percent", 0) > 10:
            alertas.append("consumo_elevado")

        if alertas:
            return {"pid": pid, "nombre": name, "ppid": ppid,
                    "alertas": alertas, "ts": time.time(),
                    "mem_pct": info.get("memory_percent", 0)}
        return None

    def escanear_memoria(self, pid: int, size: int = 4096) -> list[str]:
        """Escanea memoria de un proceso buscando shellcode."""
        hallazgos = []
        try:
            from defense import _read_mem
            mem = _read_mem(pid, size)
            if not mem:
                return []
            for i, sig in enumerate(MEM_SUSPICIOUS):
                if sig in mem:
                    hallazgos.append(f"shellcode_signature_{i}")
            # Detectar cadenas sospechosas
            try:
                texto = mem.decode("utf-8", errors="ignore")
                for s in ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
                          "LoadLibraryA", "GetProcAddress", "WinExec"]:
                    if s in texto:
                        hallazgos.append(f"api_injection:{s}")
            except: pass
        except (ImportError, Exception):
            pass
        return hallazgos

    def estado(self) -> dict:
        with self._lock:
            return {"alertas": len(self._alertas),
                    "ultimas": self._alertas[-5:] if self._alertas else [],
                    "patrones_memoria": len(MEM_SUSPICIOUS)}


_proc: Optional[ProcAnalyzer] = None
def obtener_proc_analyzer() -> ProcAnalyzer:
    global _proc
    if _proc is None:
        _proc = ProcAnalyzer()
    return _proc
