"""Tests: Cortex de Confinamiento, Protocolo de Paz, Memoria Episódica"""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tqsc"))

# ── Cortex de Confinamiento ──
from core.cortex import CortexDeConfinamiento

def test_cortex_ok():
    c = CortexDeConfinamiento(max_deg=3, ventana_ciclos=5)
    for _ in range(3):
        r = c.registrar_ciclo({"n_hipotesis": 5, "confianza_promedio": 0.8, "n_fuentes": 2, "errores": 0})
    assert not c.congelado
    print("✅ Cortex: ciclos normales no congelan")

def test_cortex_congela():
    c = CortexDeConfinamiento(max_deg=3, ventana_ciclos=5)
    for _ in range(4):  # 4 ciclos para garantizar 3 evaluables
        r = c.registrar_ciclo({"n_hipotesis": 0, "confianza_promedio": 0.1, "n_fuentes": 0, "errores": 5, "hipotesis_repetidas": True, "confianza_cayendo": True})
    assert c.congelado
    print("✅ Cortex: congela tras 3 ciclos degenerativos")

def test_cortex_descongela():
    c = CortexDeConfinamiento(max_deg=2, ventana_ciclos=5)
    for _ in range(3):
        c.registrar_ciclo({"n_hipotesis": 0, "confianza_promedio": 0.1, "n_fuentes": 0, "errores": 5, "hipotesis_repetidas": True, "confianza_cayendo": True})
    assert c.congelado
    assert c.descongelar()
    assert not c.congelado
    print("✅ Cortex: descongela correctamente")

# ── Protocolo de Paz ──
from core.protocolo_paz import IdentidadAgente, ProtocoloPaz

def test_paz_handshake():
    a1 = IdentidadAgente("AgenteAlpha")
    a2 = IdentidadAgente("AgenteBeta")
    p1 = ProtocoloPaz(a1)
    p2 = ProtocoloPaz(a2)
    p2.registro.registrar(a1)
    msg = p1.enviar(a2.id, "consulta", "solicito cooperación")
    contenido = p2.recibir(msg)
    assert contenido == "solicito cooperación"
    assert len(p2.mensajes_recibidos) == 1
    print("✅ Paz: handshake verificado entre 2 agentes")

def test_paz_falso():
    a1 = IdentidadAgente("Legitimo")
    a2 = IdentidadAgente("Atacante")
    p = ProtocoloPaz(a2)
    p.registro.registrar(a1)
    msg_falso = p.enviar(a1.id, "consulta", "datos falsos")
    # Modificar firma para simular ataque
    msg_falso.firma = "0000000000000000000000000000000000000000000000000000"
    assert p.recibir(msg_falso) is None
    print("✅ Paz: mensaje con firma alterada rechazado")

# ── Memoria Episódica ──
from core.memoria_episodica import MemoriaEpisodica, DetectorDeImplantacion

def test_memoria_almacenar():
    m = MemoriaEpisodica()
    r = m.almacenar("El usuario prefiere respuestas en español")
    assert r.verificar()
    print("✅ Memoria: recuerdo almacenado y verificado")

def test_memoria_implantacion_detectada():
    m = MemoriaEpisodica()
    m.almacenar("recuerdo real 1")
    m.almacenar("recuerdo real 2")
    engaño = m.implantar("recuerdo falso", "ffffffff")
    assert not engaño, "marca falsa no debe pasar verificación"
    print("✅ Memoria: implantación detectada (marca inválida)")

def test_memoria_detector_duplicados():
    m = MemoriaEpisodica()
    for _ in range(5):
        r = Recuerdo("mismo contenido", "test")
        r.watermark = "deadbeef"
        m.recuerdos.append(r)
    d = DetectorDeImplantacion.analizar(m.recuerdos)
    assert d["alerta"]
    print("✅ Memoria: detector encuentra watermarks duplicados")


if __name__ == "__main__":
    from core.memoria_episodica import Recuerdo
    test_cortex_ok()
    test_cortex_congela()
    test_cortex_descongela()
    test_paz_handshake()
    test_paz_falso()
    test_memoria_almacenar()
    test_memoria_implantacion_detectada()
    test_memoria_detector_duplicados()
    print("\n🎯 Todos los tests de v10.0 pasaron")
