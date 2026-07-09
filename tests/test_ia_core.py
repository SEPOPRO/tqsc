"""
TQSC v1.0 — Tests de OctaNucleo (IA Core)
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tqsc"))

from core.octa_nucleo import OctaNucleo, PatternGate, PreImpactSynthesizer, GhostMemoryZone


def test_nucleo_recibir_y_procesar():
    n = OctaNucleo("test")
    n.recibir("alerta: cpu 95%")
    n.recibir("alerta: memoria 80%")
    assert len(n.buffer) == 2
    resultados = n.procesar()
    assert len(resultados) == 2
    assert len(n.buffer) == 0
    print("✅ Nucleo: recibir + procesar")


def test_nucleo_aislar():
    n = OctaNucleo("test")
    n.aislar()
    n.recibir("ignorado")
    assert len(n.buffer) == 0
    print("✅ Nucleo: aislado ignora entradas")


def test_nucleo_shadow():
    n = OctaNucleo("test")
    n.recibir("importante")
    n.procesar()
    shadow = n.clonar_shadow()
    assert shadow.nombre == "test_shadow"
    assert len(shadow.adn_hash) > 0
    print("✅ Nucleo: shadow clonado con ADN")


def test_pattern_gate():
    assert PatternGate.validar("normal") is True
    assert PatternGate.validar("contenido bloqueado") is False
    print("✅ PatternGate: filtra correctamente")


def test_ghost_memory():
    gm = GhostMemoryZone(max_size=3)
    gm.evacuar("a")
    gm.evacuar("b")
    gm.evacuar("c")
    gm.evacuar("d")  # debe eliminar "a"
    assert len(gm.zona) == 3
    assert "a" not in gm.zona
    print("✅ GhostMemory: evacúa y limita tamaño")


if __name__ == "__main__":
    test_nucleo_recibir_y_procesar()
    test_nucleo_aislar()
    test_nucleo_shadow()
    test_pattern_gate()
    test_ghost_memory()
    print("\n🎯 Todos los tests pasaron")
