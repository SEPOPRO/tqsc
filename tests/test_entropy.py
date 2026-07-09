"""
TQSC v1.0 — Tests de EntropyNoiseEngine
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tqsc"))

from utils.entropy_engine import (
    EntropyImpactEstimator,
    EntropyShield,
    EntropyTraceLedger,
    EntropyNoiseEngine,
)


def test_estimator_mide():
    """El estimador debe producir un promedio entre 0 y 1."""
    est = EntropyImpactEstimator(muestras=3)
    promedio, anomalia = est.medir()
    assert 0 <= promedio <= 1, f"entropía fuera de rango: {promedio}"
    print(f"✅ Estimator: entropía={promedio:.4f}, anomalía={anomalia}")


def test_ledger_escribe():
    """El ledger debe escribir y firmar entradas."""
    ledger = EntropyTraceLedger(data_dir="data/test")
    entrada = ledger.registrar("test", "ok", {"valor": 42})
    assert "firma" in entrada
    assert entrada["resultado"] == "ok"
    print(f"✅ Ledger: firma={entrada['firma'][:16]}...")


def test_engine_ciclo():
    """El motor debe ejecutar un ciclo sin errores."""
    engine = EntropyNoiseEngine(data_dir="data/test")
    resultado = engine.ejecutar_ciclo()
    assert "entropia" in resultado
    assert "anomalia" in resultado
    print(f"✅ Engine: ciclo OK (entropía={resultado['entropia']})")


if __name__ == "__main__":
    test_estimator_mide()
    test_ledger_escribe()
    test_engine_ciclo()
    print("\n🎯 Todos los tests pasaron")
