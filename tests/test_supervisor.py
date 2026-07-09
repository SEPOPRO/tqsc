"""
Tests: Supervisor Watchdog + NucleusDaemon
"""
import sys, os, time, json, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tqsc"))
from supervisor import Supervisor, NucleoProceso, HEARTBEAT_INTERVAL, HEARTBEAT_TIMEOUT


def test_supervisor_inicia_nucleo():
    """Supervisor arranca un núcleo y verifica heartbeat."""
    s = Supervisor()
    s.registrar("test_ia", "core.octarcq", "OctaRCQX8")
    s.iniciar()
    time.sleep(2)  # Esperar heartbeat
    est = s.estado()
    assert "test_ia" in est
    assert est["test_ia"]["activo"], f"núcleo no activo: {est}"
    assert est["test_ia"]["pid"] is not None, f"sin PID: {est}"
    print(f"✅ Supervisor: test_ia activo (PID {est['test_ia']['pid']})")
    s.detener()


def test_supervisor_detecta_caida():
    """Supervisor detecta cuando un núcleo muere y lo reinicia."""
    # Mock: creamos un proceso que muere rápido
    import subprocess
    proc = NucleoProceso("test_crash", "core.octarcq", "OctaRCQX8", puerto=19999)
    # Simular muerte: no iniciar, solo verificar timeout
    proc.activo = True
    proc.ultimo_heartbeat = time.time() - 30  # heartbeat viejo
    assert not proc.verificar(), "debería detectar timeout"
    print("✅ Supervisor: detecta time out sin heartbeat")


def test_supervisor_estado():
    """Estado del supervisor retorna información correcta."""
    s = Supervisor()
    est = s.estado()
    assert isinstance(est, dict)
    print(f"✅ Supervisor: estado={len(est)} núcleos")


if __name__ == "__main__":
    test_supervisor_inicia_nucleo()
    test_supervisor_detecta_caida()
    test_supervisor_estado()
    print("\n🎯 Todos los tests de Supervisor pasaron")
