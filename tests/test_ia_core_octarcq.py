"""
TQSC v1.0 — Tests de OctaRCQ-X8 (IA Core completo)
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tqsc"))
from core.octarcq import OctaRCQX8


def test_ia_recibir_evento():
    ia = OctaRCQX8()
    aceptados = ia.recibir_evento("alerta: intrusión detectada en puerto 443")
    assert len(aceptados) > 0
    print("✅ IA: evento aceptado y distribuido a octantes")


def test_ia_rechazar_bloqueado():
    ia = OctaRCQX8()
    aceptados = ia.recibir_evento("contenido bloqueado: código malicioso")
    assert len(aceptados) == 0
    print("✅ IA: evento bloqueado por PatternGate")


def test_ia_rotar():
    ia = OctaRCQX8()
    ia.recibir_evento("test de rotación")
    ia.rotar()
    estado = ia.estado()
    assert len(estado["octantes"]) == 8
    print("✅ IA: rotación completa con 8 octantes")


def test_ia_shadow():
    ia = OctaRCQX8()
    ia.recibir_evento("test shadow")
    ia.rotar()
    # Verificar que los shadows se crearon
    shadows = [o for o in ia.octantes if o.shadow is not None]
    assert len(shadows) > 0
    print("✅ IA: shadow clones creados")


def test_ia_ghost():
    ia = OctaRCQX8()
    ia.recibir_evento("drop database")  # preimpact debe evacuar
    assert len(ia.ghost.zona) > 0
    print("✅ IA: ghost memory almacena eventos evacuados")


if __name__ == "__main__":
    test_ia_recibir_evento()
    test_ia_rechazar_bloqueado()
    test_ia_rotar()
    test_ia_shadow()
    test_ia_ghost()
    print("\n🎯 Todos los tests pasaron")
