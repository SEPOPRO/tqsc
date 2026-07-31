"""
tqsc/utils/fs_monitor.py — EDR: Monitoreo de filesystem en tiempo real.
Detecta archivos nuevos, modificados, eliminados en directorios críticos.
Sin watchdog (solo stdlib + psutil).
"""
import logging, os, time, threading, hashlib
from pathlib import Path
from collections import defaultdict
from typing import Optional

LOG = logging.getLogger("tqsc.fs_monitor")

# Directorios críticos a monitorear (Windows)
DIRS_CRITICOS = [
    "C:\\Windows\\System32",
    "C:\\Windows\\SysWOW64",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
]
EXT_SOSPECHOSAS = {".exe", ".dll", ".sys", ".ps1", ".vbs", ".bat", ".cmd",
                   ".js", ".vba", ".msi", ".scr", ".cpl"}
ARCHIVOS_CLAVE = [
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\Windows\\System32\\config\\SAM",
    "C:\\Windows\\System32\\config\\SYSTEM",
]


class FileSnapshot:
    """Snapshot de archivos en un directorio."""

    def __init__(self, ruta: str):
        self.ruta = Path(ruta)
        self._archivos: dict[str, tuple[float, int, str]] = {}  # path → (mtime, size, hash)
        self._tomar()

    def _tomar(self):
        if not self.ruta.exists():
            return
        try:
            for f in self.ruta.rglob("*"):
                if f.is_file() and f.suffix.lower() in EXT_SOSPECHOSAS:
                    try:
                        st = f.stat()
                        h = hashlib.sha256(f.read_bytes()).hexdigest()[:16] if st.st_size < 10*1024*1024 else ""
                        self._archivos[str(f)] = (st.st_mtime, st.st_size, h)
                    except (OSError, PermissionError):
                        pass
        except (OSError, PermissionError):
            pass

    def diff(self, otro: "FileSnapshot") -> list[str]:
        """Compara con otro snapshot. Retorta cambios."""
        cambios = []
        for path, info in self._archivos.items():
            if path not in otro._archivos:
                cambios.append(f"[NUEVO] {path}")
            else:
                old = otro._archivos[path]
                if info[0] != old[0] or info[1] != old[1]:
                    cambios.append(f"[MODIFICADO] {path} (tamaño {old[1]}→{info[1]})")
                elif info[2] and old[2] and info[2] != old[2]:
                    cambios.append(f"[HASH_DISTINTO] {path}")
        for path in otro._archivos:
            if path not in self._archivos:
                cambios.append(f"[ELIMINADO] {path}")
        return cambios


class FSMonitor:
    """Monitoreo periódico de directorios y archivos críticos."""

    def __init__(self, directorios: list[str] = None, intervalo: int = 30):
        self.directorios = directorios or []
        self.intervalo = intervalo
        self._snapshots: dict[str, FileSnapshot] = {}
        self._cambios: list[dict] = []
        self._activo = False
        self._hilo: Optional[threading.Thread] = None

    def _tomar_snapshots(self):
        self._snapshots = {}
        for d in self.directorios:
            if Path(d).exists():
                self._snapshots[d] = FileSnapshot(d)

    def escanear(self) -> list[dict]:
        """Escanea cambios desde el último snapshot."""
        cambios = []
        nuevos = {}
        for d in self.directorios:
            if not Path(d).exists():
                continue
            nuevo = FileSnapshot(d)
            prev = self._snapshots.get(d)
            if prev:
                for c in nuevo.diff(prev):
                    cambios.append({"tipo": "filesystem", "detalle": c,
                                    "ts": time.time(), "n": "fs_monitor"})
                    LOG.warning("FS: %s", c)
            nuevos[d] = nuevo
        self._snapshots = nuevos
        self._cambios.extend(cambios)
        if len(self._cambios) > 1000:
            self._cambios = self._cambios[-500:]
        return cambios

    def verificar_archivos_clave(self) -> list[str]:
        """Verifica integridad de archivos clave del sistema."""
        alterados = []
        for ruta in ARCHIVOS_CLAVE:
            p = Path(ruta)
            if p.exists():
                try:
                    h = hashlib.sha256(p.read_bytes()).hexdigest()[:16]
                    alterados.append(f"{ruta}: {h}")
                except (OSError, PermissionError):
                    alterados.append(f"{ruta}: NO_ACCESIBLE")
        return alterados

    def iniciar(self, directorios: list[str] = None):
        if self._activo:
            return
        if directorios:
            self.directorios = directorios
        if not self.directorios:
            self.directorios = DIRS_CRITICOS
        self._tomar_snapshots()
        self._activo = True
        def _loop():
            while self._activo:
                try:
                    self.escanear()
                except Exception as e:
                    LOG.error("FSMonitor: error %s", e)
                time.sleep(self.intervalo)
        self._hilo = threading.Thread(target=_loop, daemon=True, name="FSMonitor")
        self._hilo.start()
        LOG.info("FSMonitor: %d directorios, intervalo=%ds", len(self.directorios), self.intervalo)

    def detener(self):
        self._activo = False

    def estado(self) -> dict:
        return {"directorios": len(self.directorios),
                "cambios_detectados": len(self._cambios),
                "activo": self._activo}


_fs: Optional[FSMonitor] = None
def obtener_fs_monitor() -> FSMonitor:
    global _fs
    if _fs is None:
        _fs = FSMonitor()
    return _fs
