"""
Process list monitor that polls running processes at regular intervals. Does NOT intercept syscalls.
"""
import os, threading, time, logging
from datetime import datetime
from collections import defaultdict
from typing import Optional
import ctypes
from ctypes import wintypes

# IOCTL Definitions
FILE_DEVICE_UNKNOWN = 0x00000022
METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0

def CTL_CODE(DeviceType, Function, Method, Access):
    return (DeviceType << 16) | (Access << 14) | (Function << 2) | Method

IOCTL_TQSC_READ_EVENTS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_TQSC_BLOCK_PROCESS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

class TQSC_EVENT(ctypes.Structure):
    _fields_ = [
        ("PID", ctypes.c_ulong),
        ("ParentPID", ctypes.c_ulong),
        ("ImagePath", ctypes.c_wchar * 260)
    ]

try:
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    CreateFileW = kernel32.CreateFileW
    CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    CreateFileW.restype = wintypes.HANDLE
    
    DeviceIoControl = kernel32.DeviceIoControl
    DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
    DeviceIoControl.restype = wintypes.BOOL
    
    CloseHandle = kernel32.CloseHandle
    CloseHandle.argtypes = [wintypes.HANDLE]
    CloseHandle.restype = wintypes.BOOL
except Exception:
    pass

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3

from native_bridge import enum_processes as _enum_processes

try:
    import wmi
    import pythoncom
    HAS_WMI = True
except ImportError:
    HAS_WMI = False

LOG = logging.getLogger("tqsc.syscall")
TQSC_TEST = lambda: os.environ.get("TQSC_TEST_MODE") == "1"


class SyscallStats:
    """
    Estadísticas de llamadas.
    NOTA: anomalias_detectadas es actualmente siempre 0.
    """
    def __init__(self):
        self.total_calls = 0
        self.calls_por_segundo = 0
        self.picos_por_proceso: dict[int, int] = defaultdict(int)
        self.anomalias_detectadas = 0
        self.alertas_emitidas = []


class SyscallMonitor:
    """Process monitoring via Rust (tqsc_native) with Python fallback.
    TODO: Implement real syscall monitoring instead of just process polling."""

    PROCESOS_CRITICOS = [
        "NtCreateProcess", "NtCreateThreadEx", "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory", "NtProtectVirtualMemory",
        "NtReadVirtualMemory", "NtOpenProcess", "NtOpenKey",
        "NtCreateFile", "NtDeleteFile", "NtShutdownSystem",
        "CreateProcessAsUser", "CreateProcessWithToken", "CreateProcessWithLogon",
    ]

    def __init__(self, intervalo: float = 3.0):
        self.intervalo = intervalo
        self.activo = False
        self._hilo: Optional[threading.Thread] = None
        self.stats = SyscallStats()
        self._procesos_previos: set[int] = set()
        self._windows_ok = False
        self._has_driver = False
        self._driver_handle = None

        if TQSC_TEST():
            LOG.info("SyscallMonitor: MODO TEST — sin hardware real")
            return

        # Try to open driver handle
        try:
            handle = CreateFileW(
                r"\\.\TqscDriver",
                GENERIC_READ | GENERIC_WRITE,
                0,
                None,
                OPEN_EXISTING,
                0,
                None
            )
            if handle and handle != -1 and handle != ctypes.c_void_p(-1).value:
                self._has_driver = True
                self._driver_handle = handle
                LOG.info("SyscallMonitor: Conectado a \\\\.\\TqscDriver con éxito.")
            else:
                LOG.info("SyscallMonitor: No se pudo conectar al driver (fallback a WMI/polling).")
        except Exception as e:
            LOG.warning("SyscallMonitor: Error abriendo driver: %s", e)

        self._windows_ok = True
        LOG.info("SyscallMonitor: inicializado")

    def iniciar(self):
        if TQSC_TEST() or not self._windows_ok:
            LOG.info("SyscallMonitor: monitoreo simulado (test mode)")
            return
        self.activo = True
        self._hilo = threading.Thread(target=self._loop, daemon=True)
        self._hilo.start()
        LOG.info("SyscallMonitor: activo")

    def detener(self):
        self.activo = False

    def _loop(self):
        use_wmi = HAS_WMI and not TQSC_TEST() and not self._has_driver
        watcher = None
        if use_wmi:
            try:
                pythoncom.CoInitialize()
                c = wmi.WMI()
                watcher = c.Win32_ProcessStartTrace.watch_for(delay=1)
                LOG.info("SyscallMonitor: WMI watcher inicializado para Win32_ProcessStartTrace")
            except Exception as e:
                LOG.warning("SyscallMonitor: WMI falló, usando fallback. Error: %s", e)
                use_wmi = False

        while self.activo:
            try:
                if self._has_driver:
                    event = TQSC_EVENT()
                    bytes_returned = wintypes.DWORD(0)
                    res = DeviceIoControl(
                        self._driver_handle,
                        IOCTL_TQSC_READ_EVENTS,
                        None, 0,
                        ctypes.byref(event), ctypes.sizeof(event),
                        ctypes.byref(bytes_returned),
                        None
                    )
                    if res and bytes_returned.value > 0:
                        LOG.info("SyscallMonitor: Driver detectó nuevo proceso: %s (PID: %d)", event.ImagePath, event.PID)
                        self._procesos_previos.add(event.PID)
                    else:
                        time.sleep(self.intervalo)
                elif use_wmi and watcher:
                    try:
                        # Monitor with timeout to allow thread termination when self.activo is False
                        process_event = watcher(timeout_ms=int(self.intervalo * 1000))
                        if process_event:
                            pid = int(process_event.ProcessID)
                            nombre = process_event.ProcessName
                            LOG.info("SyscallMonitor: WMI detectó nuevo proceso: %s (PID: %d)", nombre, pid)
                            self._procesos_previos.add(pid)
                    except wmi.x_wmi_timed_out:
                        pass
                    except Exception as e:
                        LOG.warning("SyscallMonitor: error en WMI watcher: %s", e)
                        # Optionally fallback or just sleep
                        time.sleep(self.intervalo)
                else:
                    procs_act = self._listar_procesos()
                    nuevos = [p for p in procs_act if p["pid"] not in self._procesos_previos]
                    if nuevos:
                        LOG.info("SyscallMonitor: %d procesos nuevos detectados", len(nuevos))
                    self._procesos_previos = {p["pid"] for p in procs_act}
                    time.sleep(self.intervalo)
            except Exception as e:
                LOG.warning("SyscallMonitor: error en loop: %s", e)
                time.sleep(self.intervalo)
                
        if use_wmi:
            try:
                pythoncom.CoUninitialize()
            except Exception:
                pass
                
        if self._has_driver and self._driver_handle:
            CloseHandle(self._driver_handle)
            self._driver_handle = None

    def _listar_procesos(self) -> list[dict]:
        if TQSC_TEST():
            return [{"pid": 1, "nombre": "test", "hilos": 2, "ppid": 0}]
        try:
            procs = _enum_processes()
            if procs is None:
                raise RuntimeError("native_bridge devolvió None")
            for p in procs:
                if "nombre" not in p:
                    p["nombre"] = f"pid_{p.get('pid', 0)}"
                if "hilos" not in p:
                    p["hilos"] = 1
                if "ppid" not in p:
                    p["ppid"] = 0
            return procs
        except Exception as e:
            LOG.warning("SyscallMonitor: error listando procesos: %s", e)
            return []

    def estado(self) -> dict:
        return {
            "activo": self.activo or TQSC_TEST(),
            "procesos_monitoreados": len(self._procesos_previos),
            "ventana_segundos": self.intervalo,
            "anomalias": self.stats.anomalias_detectadas,
            "test_mode": TQSC_TEST(),
            "critical_calls_monitored": len(self.PROCESOS_CRITICOS),
            "driver_active": self._has_driver,
        }

    def bloquear_proceso(self, image_name: str) -> bool:
        if not self._has_driver:
            LOG.warning("SyscallMonitor: Driver no disponible para bloquear proceso %s", image_name)
            return False
        
        buffer = ctypes.create_unicode_buffer(image_name, 260)
        bytes_returned = wintypes.DWORD(0)
        res = DeviceIoControl(
            self._driver_handle,
            IOCTL_TQSC_BLOCK_PROCESS,
            buffer, ctypes.sizeof(buffer),
            None, 0,
            ctypes.byref(bytes_returned),
            None
        )
        if res:
            LOG.info("SyscallMonitor: Comando de bloqueo enviado para %s", image_name)
            return True
        else:
            LOG.error("SyscallMonitor: Error enviando comando de bloqueo al driver.")
            return False
