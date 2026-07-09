"""
TQSC v2.0 — Native Bridge
Puente entre Python y tqsc_native (Rust).
Si tqsc_native no está instalado, fallback graceful al código Python.
"""
import logging, os, hashlib, ctypes
from typing import Optional

LOG = logging.getLogger("tqsc.native_bridge")
TQSC_TEST = os.environ.get("TQSC_TEST_MODE") == "1"

try:
    import tqsc_native as _native
    HAS_NATIVE = True
    LOG.info("Native bridge: tqsc_native v%s cargado", _native.info()["version"])
except ImportError:
    HAS_NATIVE = False
    LOG.warning("Native bridge: tqsc_native NO disponible — usando Python fallback")


def enum_processes() -> list[dict]:
    """Enumera procesos del sistema vía Rust (tqsc_native).
    Retorna lista de dicts con pid, nombre, exe, reflectivo.
    """
    if HAS_NATIVE and not TQSC_TEST:
        return _native.enum_processes()
    # Fallback Python
    return _python_enum_processes()


def cache_disrupt(size_mb: int = 1) -> int:
    """Invalida cachés CPU vía Rust (VirtualAlloc + memset).
    Retorna bytes escritos.
    """
    if HAS_NATIVE and not TQSC_TEST:
        return _native.cache_disrupt(size_mb)
    # Fallback Python
    return _python_cache_disrupt(size_mb)


def pid_signature(pid: int) -> Optional[dict]:
    """Firma de proceso: hash del ejecutable + detección reflectivo.
    Retorna dict con pid, exe, hash_disco, reflectivo o None si falla.
    """
    if HAS_NATIVE and not TQSC_TEST:
        try:
            return _native.pid_signature(pid)
        except Exception as e:
            LOG.debug("pid_signature nativo falló para PID %d: %s", pid, e)
            return _python_pid_signature(pid)
    return _python_pid_signature(pid)


def read_process_memory(pid: int, size: int = 4096) -> Optional[bytes]:
    """Lee memoria de un proceso vía Rust."""
    if HAS_NATIVE and not TQSC_TEST:
        try:
            return bytes(_native.read_process_memory(pid, size))
        except Exception:
            return None
    return None


# ── Fallbacks Python ──────────────────────────────────────

def _python_enum_processes() -> list[dict]:
    """Python fallback para enum_processes (usa psutil)."""
    try:
        import psutil
        procs = []
        for p in psutil.process_iter(["pid", "name", "exe"]):
            try:
                exe = p.info.get("exe") or ""
                procs.append({
                    "pid": p.info["pid"],
                    "nombre": p.info["name"] or "",
                    "exe": exe,
                    "reflectivo": not exe,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return procs
    except ImportError:
        LOG.warning("psutil no disponible, enum_processes fallback vacío")
        return []


def _python_cache_disrupt(size_mb: int = 1) -> int:
    """Python fallback para cache_disrupt (usa ctypes)."""
    t = 1024 * 256 * size_mb
    try:
        if os.name == "nt":
            k32 = ctypes.windll.kernel32
            buf = k32.VirtualAlloc(None, t, 0x3000, 0x04)
            if buf:
                ctypes.memset(buf, 0xFF, t)
                k32.VirtualFree(buf, 0, 0x8000)
        else:
            import mmap
            buf = mmap.mmap(-1, t)
            buf.write(os.urandom(t))
            buf.close()
        return t
    except Exception as e:
        LOG.debug("cache_disrupt fallback falló: %s", e)
        return 0


def _python_pid_signature(pid: int) -> Optional[dict]:
    """Python fallback para pid_signature (usa psutil)."""
    try:
        import psutil
        p = psutil.Process(pid)
        exe = p.exe() if hasattr(p, "exe") else ""
        if not exe or not os.path.exists(exe):
            return {"pid": pid, "exe": "", "hash_disco": "", "reflectivo": True, "nombre": p.name()}
        with open(exe, "rb") as f:
            h = hashlib.sha256(f.read()).hexdigest()
        return {"pid": pid, "exe": exe, "hash_disco": h, "reflectivo": False}
    except Exception as e:
        LOG.debug("pid_signature fallback falló: %s", e)
        return None
