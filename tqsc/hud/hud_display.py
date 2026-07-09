"""
TQSC v1.0 — HUD Visual
Panel de monitoreo en tiempo real estilo sala de mando DEFCON.
"""
import os, time, shutil, threading
from datetime import datetime
from typing import Optional

_CLEAR = "cls" if os.name == "nt" else "clear"


class HUDDisplay:
    """Panel visual en terminal con actualización en tiempo real."""

    def __init__(self, sistema: Optional[object] = None, intervalo: float = 2.0):
        self.sistema = sistema
        self.intervalo = intervalo
        self._activo = False
        self._hilo: Optional[threading.Thread] = None

    def iniciar(self):
        self._activo = True
        self._hilo = threading.Thread(target=self._loop, daemon=True)
        self._hilo.start()

    def detener(self):
        self._activo = False

    def _loop(self):
        while self._activo:
            self._renderizar()
            time.sleep(self.intervalo)

    def _renderizar(self):
        cols = shutil.get_terminal_size().columns
        estado = self.sistema.estado() if self.sistema else {}

        # Header
        os.system(_CLEAR)
        print("╔" + "═" * (cols - 2) + "╗")
        print(f"║{'TQSC v1.0 — BlockDefender Titan Quantum Shield Core'.center(cols - 2)}║")
        print(f"║{'Sistema de Defensa Cibernética Autoevolutiva'.center(cols - 2)}║")
        print(f"║{f'{datetime.now().isoformat()}'.center(cols - 2)}║")
        print("╚" + "═" * (cols - 2) + "╝")
        print()

        # Estado de núcleos
        print("┌─ " + "NÚCLEOS ACTIVOS ".ljust(cols - 4, "─") + "┐")
        nucleos = estado.get("nucleos_activos", {})
        for nombre, activo in nucleos.items():
            icono = "🟢" if activo else "🔴"
            print(f"│ {icono} {nombre.upper().ljust(20)} {'ACTIVO' if activo else 'INACTIVO'}")
        print("└" + "─" * (cols - 2) + "┘")
        print()

        # Info adicional
        print("┌─ " + "MÉTRICAS ".ljust(cols - 4, "─") + "┐")
        print(f"│ Versión:    {estado.get('version', '?')}")
        print(f"│ Honeypot:   {estado.get('honeypot_sesiones', 0)} sesiones capturadas")
        print("└" + "─" * (cols - 2) + "┘")
        print()

        # Footer animado
        ticks = int(time.time() * 2) % 4
        spinner = "⠋⠙⠹⠸" if ticks < 4 else "⠼⠴⠦⠧"
        print(f" {spinner[ticks]} TQSC protegiendo...   [Ctrl+C para salir]")
