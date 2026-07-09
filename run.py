#!/usr/bin/env python
"""
TQSC v1.0 — Punto de entrada (CLI)
Uso: python run.py [--hud] [--test]
"""
import sys
import time
import signal
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "tqsc"))

# Test mode: set env var BEFORE importing TQSC
if "--test" in sys.argv:
    os.environ["TQSC_TEST_MODE"] = "1"

from tqsc.main import TQSC


def main():
    args = sys.argv[1:]
    modo_hud = "--hud" in args
    modo_test = "--test" in args
    modo_supervisado = "--supervised" in args

    if modo_supervisado:
        from tqsc.supervised_main import main_supervisado
        main_supervisado()
        return

    sistema = TQSC()
    sistema.iniciar()

    if modo_test:
        print("\n🧪 Modo test: ciclo completo")
        time.sleep(1)
        sistema.detener()
        print("✅ Test completado")
        return

    if modo_hud:
        from tqsc.hud.hud_display import HUDDisplay
        hud = HUDDisplay(sistema)
        hud.iniciar()
        print("🖥️  HUD activo. Presiona Ctrl+C para salir.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            hud.detener()
            sistema.detener()
            print("\n👋 TQSC detenido.")
    else:
        print(f"\n✅ TQSC operativo. {sum(sistema.nucleos_activos.values())}/9 módulos activos.")
        print("Usa --hud para interfaz visual, --test para test rápido.")
        try:
            while True:
                time.sleep(10)
                sistema.ia_core.rotar()
        except KeyboardInterrupt:
            sistema.detener()
            print("\n👋 TQSC detenido.")


if __name__ == "__main__":
    main()
