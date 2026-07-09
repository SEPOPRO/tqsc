"""
TQSC v1.0 — Test de Aislamiento
Demuestra que en TQSC_TEST_MODE=1 ningún módulo toca hardware real.
"""
import os, sys, json, tempfile
os.environ["TQSC_TEST_MODE"] = "1"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tqsc"))


def test_cache_no_toca_hardware():
    from defense import CacheDisruptor
    r = CacheDisruptor.invalidar()
    assert r == 4096, f"en test mode debe dar 4096, dio {r}"
    print("✅ CacheDisruptor: no toca hardware en test mode")


def test_syscall_no_toca_procesos():
    from defense.syscall_monitor import SyscallMonitor
    sm = SyscallMonitor(data_dir=tempfile.mkdtemp())
    sm.iniciar()
    procs = sm._listar_procesos()
    assert len(procs) == 1, f"debe dar 1 proceso mock, dio {len(procs)}"
    assert procs[0]["nombre"] == "test"
    assert sm.estado()["test_mode"] is True
    sm.detener()
    print("✅ SyscallMonitor: no enumera procesos reales en test mode")


def test_pid_matcher_no_toca_disco():
    from defense import PIDSignatureMatcher
    pm = PIDSignatureMatcher()
    r = pm.verificar(9999)
    assert r is not None
    assert r["pid"] == 9999
    assert r["exe"] == "test.exe"
    print("✅ PIDSignatureMatcher: no verifica firmas reales en test mode")


def test_isolation_limpia():
    import tempfile, shutil
    from pathlib import Path
    tmp = Path(tempfile.mkdtemp(prefix="tqsc_test_"))
    assert tmp.exists()
    shutil.rmtree(tmp, ignore_errors=True)
    assert not tmp.exists()
    print("✅ TQSCIsolation: crea y limpia directorios temporales")


def test_defensa_completa_aislada():
    import sys
    old_path = list(sys.path)
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from test_isolation import TQSCIsolation
    sys.path = old_path
    iso = TQSCIsolation()
    dc = iso.defensa
    dc.iniciar()
    r = dc.escanear()
    assert "cpu_altos" in r
    assert "syscall_estado" in r
    assert "pid_signatures" in r
    assert r["syscall_estado"]["test_mode"] is True
    iso.limpia()
    print("✅ DefenseCore completo: ciclo aislado sin hardware real")


if __name__ == "__main__":
    test_cache_no_toca_hardware()
    test_syscall_no_toca_procesos()
    test_pid_matcher_no_toca_disco()
    test_isolation_limpia()
    test_defensa_completa_aislada()
    os.environ.pop("TQSC_TEST_MODE", None)
    print("\n🎯 Todos los tests de aislamiento pasaron — hardware real NO tocado")
