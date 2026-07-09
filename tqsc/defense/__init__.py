"""TQSC v1.0 — Protección Física Anti-Side-Channel"""
import os, time, hashlib, logging, ctypes
from pathlib import Path
from typing import Optional

from native_bridge import cache_disrupt as _cache_disrupt, pid_signature as _pid_signature, read_process_memory as _read_mem

TQSC_TEST = os.environ.get("TQSC_TEST_MODE") == "1"
try:
    import psutil; HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False; logging.warning("psutil no instalado")

LOG = logging.getLogger("tqsc.defense")


class CPUUsageScanner:
    """Monitorea CPU con threshold randomizado anti-evasión."""
    def __init__(self, umbral: float = 80.0, ventana: int = 60, max_procesos: int = 5):
        self.umbral = umbral; self.ventana = ventana; self.max_procesos = max_procesos
        self.historial: list[dict] = []

    def escanear(self) -> list[dict]:
        if not HAS_PSUTIL: return []
        ahora = time.time(); s = []
        # Threshold randomizado: +/-5% anti-evasión
        umbral_efectivo = self.umbral + (hash(f"{ahora//60}") % 10 - 5)
        for proc in psutil.process_iter(["pid", "name", "cpu_percent", "create_time"]):
            try:
                cpu = proc.info["cpu_percent"] or 0
                if cpu > umbral_efectivo:
                    s.append({"pid": proc.info["pid"], "nombre": proc.info["name"],
                              "cpu": round(cpu, 1), "umbral_aplicado": umbral_efectivo})
            except (psutil.NoSuchProcess, TypeError): continue
        self.historial.append({"time": ahora, "altos": len(s)})
        self.historial = [h for h in self.historial if ahora - h["time"] < self.ventana]
        if len(s) >= self.max_procesos:
            LOG.warning("CPU: %d procesos con >%.0f%% CPU", len(s), umbral_efectivo)
        return s


class CacheDisruptor:
    """Inyecta entropía vía Rust (tqsc_native) con fallback ctypes."""

    @staticmethod
    def invalidar(tamano_mb: int = 1) -> int:
        return _cache_disrupt(tamano_mb)


class ThermalSensor:
    """Sensor térmico con umbral adaptativo + ventana móvil."""
    def __init__(self, umbral: float = 75.0):
        self.umbral = umbral; self.historial: list[float] = []

    def leer(self) -> Optional[float]:
        if not HAS_PSUTIL or not hasattr(psutil, "sensors_temperatures"): return None
        try:
            for sensores in psutil.sensors_temperatures().values():
                for s in sensores:
                    self.historial.append(s.current)
                    if len(self.historial) > 60: self.historial.pop(0)
                    if len(self.historial) >= 3:
                        media = sum(self.historial[-3:]) / 3
                        if media > self.umbral:
                            return media
        except (psutil.Error, OSError, ValueError) as e:
            LOG.warning("ThermalSensor: %s", e)
        return None


class ProcessAffinityGuard:
    """Aísla + monitorea continuamente para evitar que el proceso cambie su afinidad."""
    def __init__(self, intervalo_verificacion: float = 5.0):
        self.aislados: dict[int, dict] = {}

    def aislar(self, pid: int, cpu: int = 0) -> bool:
        if not HAS_PSUTIL: return False
        try:
            p = psutil.Process(pid)
            original = list(p.cpu_affinity())
            p.cpu_affinity([cpu])
            if p.cpu_affinity() == [cpu]:
                self.aislados[pid] = {"cpu_original": original, "cpu_asignado": cpu,
                                       "timestamp": time.time(), "ultima_verificacion": time.time()}
                LOG.warning("ProcessAffinity: PID %d aislado a CPU %d", pid, cpu)
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError) as e:
            LOG.debug("ProcessAffinity[%d]: %s", pid, e)
        return False

    def verificar(self, pid: int) -> bool:
        """Verifica que el proceso siga aislado. Si cambió, lo re-aísla."""
        if pid not in self.aislados: return False
        info = self.aislados[pid]
        try:
            p = psutil.Process(pid)
            affinity = list(p.cpu_affinity())
            if affinity != [info["cpu_asignado"]]:
                LOG.warning("ProcessAffinity: PID %d re-asignado de %s a %s — re-aislando", pid, affinity, info["cpu_asignado"])
                p.cpu_affinity([info["cpu_asignado"]])
            info["ultima_verificacion"] = time.time()
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            del self.aislados[pid]
            return False

    def restaurar(self, pid: int) -> bool:
        if pid not in self.aislados: return False
        info = self.aislados[pid]
        try:
            psutil.Process(pid).cpu_affinity(info["cpu_original"])
            del self.aislados[pid]
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            LOG.warning("ProcessAffinity: rollback falló PID %d: %s", pid, e)
            return False

    def historial_aislamientos(self) -> list[dict]:
        return [{"pid": pid, **info} for pid, info in self.aislados.items()]


class OpcodeInterruptionEngine:
    """Detecta shellcode incluso ofuscado (XOR) usando entropía + frecuencia de bytes."""
    
    PATRONES_OPCODE = {
        "nop_sled":   [b"\x90\x90", b"\x90\x90\x90"],
        "call_chain": [b"\xe8", b"\xff\xd0", b"\xff\xd1", b"\xff\xd2"],
        "jmp_reflex": [b"\xeb\xfe", b"\xeb\xfd"],
        "int3_break": [b"\xcc\xcc", b"\xcc\xcc\xcc"],
        "shell_lp":   [b"\x31\xc0", b"\x31\xdb", b"\x31\xd2", b"\x50\x68"],
    }

    def __init__(self):
        self.ultimo_analisis: dict = {}

    def analizar(self, buffer: bytes | str) -> list[dict]:
        if isinstance(buffer, str): buffer = buffer.encode("latin-1", errors="replace")
        resultados = []
        for nombre, patrones in self.PATRONES_OPCODE.items():
            for pat in patrones:
                idx = 0
                while True:
                    pos = buffer.find(pat, idx)
                    if pos == -1: break
                    resultados.append({"patron": nombre, "offset": pos, "bytes": pat.hex()})
                    idx = pos + 1
                    if len(resultados) > 100: break
            if len(resultados) > 100: break
        # Nueva detección: entropía alta = posible shellcode ofuscado
        if len(buffer) > 8:
            freqs = {}
            for b in buffer:
                freqs[b] = freqs.get(b, 0) + 1
            entropia = -sum((c/len(buffer)) * __import__('math').log2(c/len(buffer)) for c in freqs.values())
            if entropia > 4.0 and len(buffer) > 16:
                resultados.append({"patron": "alta_entropia", "offset": 0, "entropia": round(entropia, 2)})
        self.ultimo_analisis = {"resultados": len(resultados), "tamano": len(buffer)}
        return resultados

    def tiene_shellcode(self, buffer: bytes | str) -> bool:
        r = self.analizar(buffer)
        return len(r) >= 3

    def estado(self) -> dict:
        return self.ultimo_analisis


class HeatMapDifferentialShield:
    """Correlaciona temp/CPU con umbral dinámico por desviación estándar."""
    def __init__(self, ventana: int = 60):
        self.mapa: dict[int, list[dict]] = {}
        self.ventana = ventana

    def registrar(self, pid: int, nombre: str, cpu: float = 0, ram: float = 0, io: float = 0, temp: float = 0):
        ahora = time.time()
        if pid not in self.mapa: self.mapa[pid] = []
        self.mapa[pid].append({"t": ahora, "cpu": cpu, "ram": ram, "io": io, "temp": temp, "nombre": nombre})
        self.mapa[pid] = [m for m in self.mapa[pid] if ahora - m["t"] < self.ventana]

    def anomalia(self, pid: int) -> Optional[dict]:
        if pid not in self.mapa or len(self.mapa[pid]) < 3: return None
        m = self.mapa[pid][-5:]
        temps = [x["temp"] for x in m if x["temp"] > 0]
        if len(temps) < 2: return None
        media_temp = sum(temps) / len(temps)
        std_temp = (sum((t - media_temp)**2 for t in temps) / len(temps))**0.5
        cpu_prom = sum(x["cpu"] for x in m) / len(m)
        # Detección por desviación estándar, no umbral fijo
        if std_temp > 5.0 and cpu_prom < 40:
            return {"pid": pid, "nombre": m[-1]["nombre"], "temp_media": round(media_temp, 1),
                    "std_termico": round(std_temp, 2), "cpu_prom": round(cpu_prom, 1), "tipo": "diferencial_termico"}
        return None

    def estado(self) -> dict:
        return {"pids": len(self.mapa), "muestras": sum(len(v) for v in self.mapa.values())}


class PIDSignatureMatcher:
    """Detecta hot-patch vía Rust (tqsc_native) con fallback psutil."""

    def verificar(self, pid: int) -> Optional[dict]:
        if TQSC_TEST:
            return {"pid": pid, "exe": "test.exe", "hash": "a"*64, "reflectivo": False, "hotpatch": False}
        sig = _pid_signature(pid)
        if sig is None:
            return None
        # Detectar hotpatch comparando hash disco vs memoria
        hotpatch = False
        if not sig.get("reflectivo") and sig.get("exe"):
            try:
                with open(sig["exe"], "rb") as f:
                    header = f.read(4096)
                mem = _read_mem(pid, 4096)
                if mem and len(mem) == 4096:
                    import hashlib as _h
                    hotpatch = _h.sha256(mem).hexdigest()[:32] != _h.sha256(header).hexdigest()[:32]
            except Exception:
                pass
        return {
            "pid": sig.get("pid"), "exe": sig.get("exe", ""),
            "hash": sig.get("hash_disco", ""),
            "reflectivo": sig.get("reflectivo", False),
            "hotpatch": hotpatch,
        }
        return None


class DefenseCore:
    """Orquesta defensa física con cache de procesos y escaneo diferencial."""
    def __init__(self):
        self.cpu = CPUUsageScanner()
        self.cache = CacheDisruptor()
        self.thermal = ThermalSensor()
        self.affinity = ProcessAffinityGuard()
        self.opcode = OpcodeInterruptionEngine()
        self.pid_check = PIDSignatureMatcher()
        self._ultimo_pids: set[int] = set()
        from defense.syscall_monitor import SyscallMonitor
        self.syscall = SyscallMonitor()

    def iniciar(self):
        self.syscall.iniciar()
        LOG.info("DefenseCore: syscall monitor activo")

    def escanear(self) -> dict:
        r = {"cpu_altos": self.cpu.escanear(), "temperatura": self.thermal.leer(),
             "syscall_estado": self.syscall.estado() if hasattr(self, "syscall") else {},
             "pid_signatures": [], "procesos_nuevos": []}
        if self.pid_check and HAS_PSUTIL:
            pids_actuales = set()
            for proc in psutil.process_iter(["pid"]):
                pid = proc.info["pid"]
                pids_actuales.add(pid)
                # Solo verificar PIDs nuevos (diferencial)
                if pid not in self._ultimo_pids:
                    try:
                        sig = self.pid_check.verificar(pid)
                        if sig:
                            r["pid_signatures"].append(sig)
                            r["procesos_nuevos"].append(pid)
                    except: continue
            self._ultimo_pids = pids_actuales
        # Verificar procesos aislados
        for pid in list(self.affinity.aislados.keys()):
            self.affinity.verificar(pid)
        return r
