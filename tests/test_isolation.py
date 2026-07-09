"""
TQSC v1.0 — Test Isolation Framework
======================================
Proporciona:
  - Directorios temporales que se limpian automáticamente
  - Mocks para hardware real (VirtualAlloc, procesos, sockets, sensores)
  - Aislamiento total: ningún test toca el sistema real

Uso:
  from test_isolation import TQSCIsolation
  iso = TQSCIsolation()
  iso.defense.escanear()  # usa mock, no hardware real
  iso.cleanup()           # borra todo
"""
import os, sys, tempfile, time, json, hashlib
from pathlib import Path
from unittest.mock import MagicMock, patch
from typing import Optional


class TQSCIsolation:
    """Entorno de pruebas aislado para TQSC.
    
    Crea directorios temporales, parchea módulos de hardware,
    y provee métodos para verificar comportamiento sin riesgo.
    """

    def __init__(self):
        self._tmp = Path(tempfile.mkdtemp(prefix="tqsc_test_"))
        self._patchers: list = []
        self._activo = True
        os.environ["TQSC_TEST_MODE"] = "1"
        self._configurar_mocks()

    def _configurar_mocks(self):
        """Parchea módulos que tocan hardware real."""
        import defense
        import defense.syscall_monitor

        # Mock de VirtualAlloc
        mock_kernel32 = MagicMock()
        mock_kernel32.VirtualAlloc.return_value = 0xDEADBEEF
        mock_kernel32.VirtualFree.return_value = True

        # Mock de psutil
        mock_psutil = MagicMock()
        mock_proc = MagicMock()
        mock_proc.info = {"pid": 1234, "name": "test.exe", "cpu_percent": 5,
                          "memory_info": MagicMock(rss=1024*1024)}
        mock_psutil.process_iter.return_value = [mock_proc]
        mock_psutil.Process.return_value = mock_proc
        mock_psutil.net_io_counters.return_value = MagicMock(bytes_sent=1000, bytes_recv=1000)

        # Aplicar patches
        if os.name == "nt":
            p1 = patch("defense.syscall_monitor.ctypes.windll.kernel32", mock_kernel32)
            p2 = patch("defense.syscall_monitor.ctypes.windll.ntdll", MagicMock())
            p1.start(); p2.start()
            self._patchers.extend([p1, p2])

        p3 = patch("defense.psutil", mock_psutil)
        p3.start()
        self._patchers.append(p3)

    @property
    def data_dir(self) -> str:
        return str(self._tmp)

    @property
    def defensa(self):
        from defense import DefenseCore
        return DefenseCore()

    @property
    def syscall_monitor(self):
        from defense.syscall_monitor import SyscallMonitor
        return SyscallMonitor(data_dir=self.data_dir)

    @property
    def blockchain(self):
        from blockchain.fork_sealant import ForkSealant, CrossChainTracker
        return ForkSealant(data_dir=self.data_dir)

    def limpia(self):
        """Limpia el entorno de pruebas."""
        for p in self._patchers:
            try: p.stop()
            except: pass
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)
        os.environ.pop("TQSC_TEST_MODE", None)
        self._activo = False


def aisla(func):
    """Decorador: ejecuta la función dentro de un entorno aislado."""
    def wrapper(*args, **kwargs):
        iso = TQSCIsolation()
        try:
            return func(iso, *args, **kwargs)
        finally:
            iso.limpia()
    return wrapper
