"""
TQSC v1.0 — Tests de NodeReputationManager y NodeChallenge
"""
import sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tqsc"))
from blockchain.fork_sealant import NodeReputationManager, NodeChallenge, DEFAULT_NODOS


def test_reputacion_inicial():
    r = NodeReputationManager(DEFAULT_NODOS)
    assert all(r.esta_comprometido(n) == False for n in DEFAULT_NODOS)
    assert len(r.nodos_confiables()) == len(DEFAULT_NODOS)


def test_reputacion_penaliza():
    r = NodeReputationManager(DEFAULT_NODOS)
    for _ in range(5):
        r.registrar_voto("Nodo_C", False)  # votos inconsistentes
    assert r.esta_comprometido("Nodo_C")
    assert "Nodo_C" not in r.nodos_confiables()
    print("✅ Reputación: nodo comprometido excluido")


def test_reputacion_recupera():
    r = NodeReputationManager(DEFAULT_NODOS)
    for _ in range(3):
        r.penalizar("Nodo_B", "test")
    assert r.esta_comprometido("Nodo_B")
    for _ in range(10):
        r.registrar_voto("Nodo_B", True)  # recuperar con votos buenos
    assert not r.esta_comprometido("Nodo_B")
    print("✅ Reputación: nodo se recupera con votos consistentes")


def test_challenge_exitoso():
    r = NodeReputationManager(DEFAULT_NODOS)
    c = NodeChallenge(r)
    nonce = c.lanzar("Nodo_A")
    clave = c.claves["Nodo_A"]
    import hashlib
    respuesta = hashlib.sha256(f"{nonce}{clave}".encode()).hexdigest()
    assert c.verificar_respuesta("Nodo_A", nonce, respuesta)
    print("✅ Challenge: respuesta correcta aceptada")


def test_challenge_timeout():
    r = NodeReputationManager(DEFAULT_NODOS)
    c = NodeChallenge(r)
    nonce = c.lanzar("Nodo_B")
    import hashlib
    clave = c.claves["Nodo_B"]
    respuesta = hashlib.sha256(f"{nonce}{clave}".encode()).hexdigest()
    # No esperamos, el timeout es 5s pero el nonce ya no está en activos
    assert c.verificar_respuesta("Nodo_B", nonce, respuesta)
    print("✅ Challenge: respuesta dentro de tiempo aceptada")


def test_challenge_respuesta_incorrecta():
    r = NodeReputationManager(DEFAULT_NODOS)
    c = NodeChallenge(r)
    nonce = c.lanzar("Nodo_C")
    assert not c.verificar_respuesta("Nodo_C", nonce, "hash_falso")
    assert r.scores["Nodo_C"] < 1.0  # penalizado pero no necesariamente comprometido
    print("✅ Challenge: respuesta incorrecta → penalización aplicada")


if __name__ == "__main__":
    test_reputacion_inicial()
    test_reputacion_penaliza()
    test_reputacion_recupera()
    test_challenge_exitoso()
    test_challenge_timeout()
    test_challenge_respuesta_incorrecta()
    print("\n🎯 Todos los tests de reputación pasaron")
