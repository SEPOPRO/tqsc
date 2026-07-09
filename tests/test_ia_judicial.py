"""
Tests: IAJudicialInterna + EthicalConsensusGate (producción)
"""
import sys, os, json, tempfile
from pathlib import Path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tqsc"))
from ia import IAJudicialInterna, EthicalConsensusGate


def test_judicial_bloquea_destructivas():
    j = IAJudicialInterna(data_dir=tempfile.mkdtemp())
    assert j.juzgar("delete_system") is False, "delete_system debe bloquearse"
    assert j.juzgar("shutdown_all") is False, "shutdown_all debe bloquearse"
    assert j.juzgar("rm -rf /") is False, "rm -rf / debe bloquearse"
    print("✅ Judicial: acciones destructivas bloqueadas")


def test_judicial_permite_inocuas():
    j = IAJudicialInterna(data_dir=tempfile.mkdtemp())
    assert j.juzgar("listar directorio") is True, "listar no debe bloquearse"
    assert j.juzgar("echo hola") is True, "echo no debe bloquearse"
    print("✅ Judicial: acciones inocuas permitidas")


def test_judicial_historial():
    j = IAJudicialInterna(data_dir=tempfile.mkdtemp())
    j.juzgar("delete_system")
    j.juzgar("echo test")
    assert len(j.historial) == 2
    assert j.historial[0]["aceptable"] is False
    assert j.historial[1]["aceptable"] is True
    print("✅ Judicial: historial con 2 decisiones correctas")


def test_judicial_exportar():
    j = IAJudicialInterna(data_dir=tempfile.mkdtemp())
    j.juzgar("ddos", {"origen": "test"})
    ruta = j.exportar_auditoria()
    assert os.path.exists(ruta)
    from utils.secure_storage import read as _read
    data = _read(Path(ruta))
    assert data is not None and len(data) > 0
    assert len(data) == 1
    assert data[0]["accion"] == "ddos"
    print("✅ Judicial: exportación a JSON exitosa")


def test_judicial_agregar_regla():
    j = IAJudicialInterna(data_dir=tempfile.mkdtemp())
    j.agregar_regla("custom", "evil_command", 9, "comando malvado")
    assert j.juzgar("evil_command --all") is False
    print("✅ Judicial: regla dinámica funciona")


def test_judicial_estado():
    j = IAJudicialInterna(data_dir=tempfile.mkdtemp())
    j.juzgar("delete_system")
    j.juzgar("echo ok")
    e = j.estado()
    assert e["reglas"] >= 10  # reglas predefinidas
    assert e["decisiones_totales"] == 2
    assert e["bloqueadas"] == 1
    print("✅ Judicial: estado() retorna métricas correctas")


def test_ethical_gate_ponderado():
    g = EthicalConsensusGate()
    # 3 votos a favor con peso 1.0 → 100% → pasa
    assert g.decidir([(True, 1.0), (True, 1.0), (True, 1.0)]) is True
    # 1 a favor (1.0), 2 en contra (1.0 c/u) → 33% → no pasa
    assert g.decidir([(True, 1.0), (False, 1.0), (False, 1.0)]) is False
    print("✅ EthicalGate: voto ponderado correcto")


def test_ethical_gate_pesos_desiguales():
    g = EthicalConsensusGate()
    # 1 a favor con peso 5.0, 2 en contra con peso 1.0 c/u → 5/7=71%→ pasa
    assert g.decidir([(True, 5.0), (False, 1.0), (False, 1.0)]) is True
    print("✅ EthicalGate: pesos desiguales funcionan")


def test_ethical_gate_vacio():
    g = EthicalConsensusGate()
    assert g.decidir([]) is False
    print("✅ EthicalGate: lista vacía → False")


def test_ethical_gate_simple():
    assert EthicalConsensusGate.decidir_simple([True, True, False]) is True
    assert EthicalConsensusGate.decidir_simple([True, False, False]) is False
    assert EthicalConsensusGate.decidir_simple([]) is False
    print("✅ EthicalGate: modo simple funciona")


if __name__ == "__main__":
    test_judicial_bloquea_destructivas()
    test_judicial_permite_inocuas()
    test_judicial_historial()
    test_judicial_exportar()
    test_judicial_agregar_regla()
    test_judicial_estado()
    test_ethical_gate_ponderado()
    test_ethical_gate_pesos_desiguales()
    test_ethical_gate_vacio()
    test_ethical_gate_simple()
    print("\n🎯 Todos los tests de IA Judicial + Ethical Gate pasaron")
