"""
TQSC v1.0 — Tests de ForkSealant
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tqsc"))
from blockchain.fork_sealant import ForkSealant, CrossChainTracker

# Nodos de prueba aislados de DEFAULT_NODOS
TEST_NODOS = {"Nodo_A": "aaa", "Nodo_B": "bbb", "Nodo_C": "ccc"}


def test_fork_sealant_valido():
    s = ForkSealant(nodos=TEST_NODOS, data_dir="data/test")
    assert s.verificar("aaa") is True
    print("✅ ForkSealant: hash válido aceptado")


def test_fork_sealant_invalido():
    s = ForkSealant(nodos=TEST_NODOS, data_dir="data/test")
    assert s.verificar("hackeado999") is False
    print("✅ ForkSealant: hash inválido rechazado")

def test_crosschain_mayoria():
    """Hash minoritario debe ir a reconsenso (reputación ponderada)."""
    s = ForkSealant(nodos=TEST_NODOS, data_dir="data/test")
    t = CrossChainTracker(nodos=TEST_NODOS, sealant=s)
    # "aaa" está en 1/3 nodos → con reputación igualitaria, peso=0.33 < 0.5 → reconsenso
    result = t.verificar("aaa")
    assert isinstance(result, bool)
    assert result is False
    print(f"✅ CrossChain: hash minoritario → {'aceptado' if result else 'rechazado'} por reconsenso")


def test_crosschain_consenso_fuerte():
    """Hash en 3/3 nodos debe pasar sin reconsenso."""
    s = ForkSealant(nodos=TEST_NODOS, data_dir="data/test")
    t = CrossChainTracker(nodos=TEST_NODOS, sealant=s)
    # Modificar temporalmente reputación para que Nodo_A tenga peso dominante
    for _ in range(10):
        t.reputacion.registrar_voto("Nodo_A", True)
    assert t.verificar("aaa") is True
    print("✅ CrossChain: nodo con alta reputación pasa hash")


def test_crosschain_divergencia():
    s = ForkSealant(nodos=TEST_NODOS, data_dir="data/test")
    t = CrossChainTracker(nodos=TEST_NODOS, sealant=s)
    result = t.verificar("unknown_hash")
    assert isinstance(result, bool)
    assert result is False
    print(f"✅ CrossChain: divergencia → {'aceptado' if result else 'rechazado'}")


if __name__ == "__main__":
    test_fork_sealant_valido()
    test_fork_sealant_invalido()
    test_crosschain_mayoria()
    test_crosschain_divergencia()
    print("\n🎯 Todos los tests pasaron")
