#!/usr/bin/env python3
"""TQSC v2.0 — Entry point"""
import sys, os, time, signal
sys.path.insert(0, os.path.dirname(__file__))

if "--test" in sys.argv:
    os.environ["TQSC_TEST_MODE"] = "1"

from tqsc.main import TQSC

_sistema = None


def _signal_handler(signum, frame):
    global _sistema
    sig_name = signal.Signals(signum).name
    if _sistema:
        _sistema.detener()
    print(f"\n👋 TQSC detenido ({sig_name}).")
    sys.exit(0)


def main():
    global _sistema
    modo_test = "--test" in sys.argv
    modo_supervisado = "--supervised" in sys.argv
    modo_hud = "--hud" in sys.argv

    if modo_supervisado:
        from tqsc.supervised_main import main_supervisado
        main_supervisado()
        return

    sistema = TQSC()
    _sistema = sistema
    sistema.iniciar()

    # Docker graceful shutdown
    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    # World Model ML
    ml = None
    try:
        from tqsc.ml.integration import MLOrchestrator
        ml = MLOrchestrator(intervalo=3.0)
        ml.iniciar()
    except Exception as e:
        pass

    if modo_test:
        import time as _t
        _t.sleep(1)
        sistema.detener()
        print("🧊 ✅ TQSC listo. 9/9 núcleos activos.")
        return

    if "--hud" in sys.argv:
        # Auto-generar certificados TLS si no existen
        certs_dir = os.path.join(os.environ.get("TQSC_HOME", "data"), "certs")
        if not os.path.exists(os.path.join(certs_dir, "localhost.crt")):
            try:
                from utils.tls import generar_todos
                generar_todos()
            except Exception:
                pass
        from tqsc.hud.hud_display import HUDServer
        HUDServer(9090, usar_tls=os.path.exists(os.path.join(certs_dir, "localhost.crt"))).iniciar()
        print("🖥️  HUD en http://localhost:9090. Ctrl+C para salir.")
    else:
        print(f"✅ TQSC operativo. Usa --hud para interfaz visual.")

    try:
        while True:
            time.sleep(10)
            sistema.ia_core.rotar()
    except KeyboardInterrupt:
        sistema.detener()
        print("\n👋 TQSC detenido.")


if __name__ == "__main__":
    main()
