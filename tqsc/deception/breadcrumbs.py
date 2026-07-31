"""
tqsc/deception/breadcrumbs.py — Breadcrumbs en memoria, env, y config.
"""
import logging, os, secrets, ctypes
from pathlib import Path
from typing import Optional

LOG = logging.getLogger("tqsc.deception.breadcrumbs")


class Breadcrumbs:
    """Planta credenciales senuelo en memoria del proceso, env, y archivos."""

    def __init__(self, tqsc_home: str = "data"):
        self._tqsc_home = tqsc_home
        self._total = 0
        self._buffers: list[ctypes.Array] = []  # Referencias persistentes

    def plantar_en_memoria(self, cantidad: int = 5):
        """Planta strings en heap de Python con referencia persistente.
        No usa variables locales que GC pueda recolectar."""
        for _ in range(cantidad):
            valor = f"{secrets.token_hex(16)}-{secrets.token_urlsafe(12)}"
            buf = ctypes.create_string_buffer(valor.encode())
            self._buffers.append(buf)
            self._total += 1
            LOG.debug("🍞 Breadcrumb heap @ %s", hex(ctypes.addressof(buf)))

    def plantar_en_env(self, cantidad: int = 3):
        for _ in range(cantidad):
            nombre = f"TQSC_{secrets.token_hex(4).upper()}_SECRET"
            os.environ[nombre] = f"sk-{secrets.token_hex(32)}"
            self._total += 1

    def plantar_en_config(self, ruta: Optional[str] = None):
        ruta = ruta or os.path.join(self._tqsc_home, ".env")
        try:
            Path(ruta).parent.mkdir(parents=True, exist_ok=True)
            with open(ruta, "a") as f:
                for _ in range(3):
                    f.write(f"TQSC_SECRET_{secrets.token_hex(4).upper()}={secrets.token_urlsafe(24)}\n")
                    self._total += 1
        except (OSError, PermissionError):
            pass

    def iniciar(self):
        self.plantar_en_memoria(5)
        self.plantar_en_env(3)
        self.plantar_en_config()

    def detener(self):
        pass

    def estado(self) -> dict:
        return {"total": self._total, "buffers_activos": len(self._buffers)}
