"""
tqsc/utils/registry_monitor.py — EDR: Monitoreo de registro de Windows.
Detecta persistencia maliciosa (run, services, scheduled tasks).
Solo Windows (ctypes + winreg).
"""
import logging, os, time, threading
from typing import Optional

LOG = logging.getLogger("tqsc.registry")

# Claves de registro con alto riesgo de persistencia maliciosa
PERSISTENCE_KEYS = [
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU"),
    (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "HKCU"),
    (r"SYSTEM\CurrentControlSet\Services", "HKLM"),
    (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "HKLM"),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", "HKCU"),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM"),
    (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache", "HKLM"),
]


class RegistrySnapshot:
    """Snapshot de valores de registro."""

    def __init__(self, claves: list[tuple] = None):
        self.claves = claves or PERSISTENCE_KEYS
        self._valores: dict[str, list[tuple[str, str]]] = {}  # key → [(name, value)]
        self._tomar()

    def _tomar(self):
        import winreg
        hive_map = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
        for subkey, hive_name in self.claves:
            hive = hive_map.get(hive_name)
            if not hive:
                continue
            try:
                with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                    vals = []
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            vals.append((str(name), str(value)[:200]))
                            i += 1
                        except OSError:
                            break
                    if vals:
                        self._valores[f"{hive_name}\\{subkey}"] = vals
            except (OSError, PermissionError, FileNotFoundError):
                pass

    def diff(self, otro: "RegistrySnapshot") -> list[str]:
        cambios = []
        for key, vals in self._valores.items():
            old = otro._valores.get(key, [])
            old_dict = dict(old)
            for name, value in vals:
                if name not in old_dict:
                    cambios.append(f"[NUEVO] {key}\\{name} = {value[:80]}")
                elif old_dict[name] != value:
                    cambios.append(f"[MODIFICADO] {key}\\{name}: {old_dict[name][:40]} → {value[:40]}")
        for key in otro._valores:
            if key not in self._valores:
                cambios.append(f"[ELIMINADA] clave {key}")
        return cambios


class RegistryMonitor:
    """Monitoreo de cambios en registro de Windows."""

    def __init__(self, intervalo: int = 60):
        self.intervalo = intervalo
        self._snapshot: Optional[RegistrySnapshot] = None
        self._cambios: list[str] = []
        self._activo = False
        self._hilo: Optional[threading.Thread] = None

    def escanear(self) -> list[str]:
        """Escanea cambios desde el último snapshot."""
        if not self._snapshot:
            self._snapshot = RegistrySnapshot()
            return []
        try:
            nuevo = RegistrySnapshot()
            cambios = nuevo.diff(self._snapshot)
            self._snapshot = nuevo
            self._cambios.extend(cambios)
            if len(self._cambios) > 1000:
                self._cambios = self._cambios[-500:]
            for c in cambios:
                LOG.warning("Registry: %s", c)
            return cambios
        except Exception as e:
            LOG.warning("Registry: error %s", e)
            return []

    def iniciar(self):
        if self._activo:
            return
        self._activo = True
        def _loop():
            while self._activo:
                try:
                    self.escanear()
                except Exception:
                    pass
                time.sleep(self.intervalo)
        self._hilo = threading.Thread(target=_loop, daemon=True, name="RegistryMonitor")
        self._hilo.start()
        LOG.info("RegistryMonitor: %d claves, intervalo=%ds", len(PERSISTENCE_KEYS), self.intervalo)

    def detener(self):
        self._activo = False

    def estado(self) -> dict:
        return {"claves": len(PERSISTENCE_KEYS),
                "cambios": len(self._cambios),
                "activo": self._activo,
                "windows": os.name == "nt"}


_reg: Optional[RegistryMonitor] = None
def obtener_registry_monitor() -> RegistryMonitor:
    global _reg
    if _reg is None:
        _reg = RegistryMonitor()
    return _reg
