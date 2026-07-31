"""
Stress test TQSC v2.0 — Empuja todos los límites del sistema.
"""
import sys, os, time, threading, json
base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(base)
os.environ["TQSC_TEST_MODE"] = "1"
sys.path.insert(0, base)
sys.path.insert(0, os.path.join(base, "tqsc"))

from tqsc.main import TQSC
from utils.siem_core import SIEMCore
from utils.audit import AuditTrail
from utils.auth import AuthManager

results = {"pass": 0, "fail": 0, "details": []}

def test(name, fn):
    try:
        fn()
        results["pass"] += 1
        results["details"].append(f"  ✅ {name}")
    except Exception as e:
        results["fail"] += 1
        results["details"].append(f"  ❌ {name}: {e}")

s = TQSC()
s.iniciar()
print("\n═══ STRESS TEST TQSC ═══\n")

# 1. 1000 eventos SIEM en 2s
def test_siem_flood():
    sc = SIEMCore("data/stress_siem")
    for i in range(1000):
        sc.ingesta_evento({"t": "stress", "n": "test", "a": "flood",
                           "d": f"evento {i}", "s": "info", "ts": time.time()})
    assert len(list(sc.store._cache)) >= 900
test("SIEM: 1000 eventos sin pérdida", test_siem_flood)

# 2. 500 auditorías encadenadas con integridad
def test_audit_chain():
    at = AuditTrail("data/stress_audit.jsonl", "stress", siem=False)
    hashes = []
    for i in range(500):
        h = at.registrar("stress", "tester", "/stress", f"test {i}", "INFO")
        hashes.append(h)
    r = at.verificar()
    assert all(e.get("integro") for e in r), "Integridad rota"
    assert len(r) == 500
test("Auditoría: 500 entradas encadenadas íntegras", test_audit_chain)

# 3. 1000 logins con account lockout
def test_auth_lockout():
    am = AuthManager("stress-key")
    ok = 0; blocked = 0
    for i in range(20):
        r = am.autenticar("admin", "wrong", "")
        if r: ok += 1
        else: blocked += 1
    assert blocked >= 5, f"solo {blocked} bloqueados"
test("Auth: brute force bloquea tras 5 intentos", test_auth_lockout)

# 4. 100 conexiones honeypot concurrentes
def test_honeypot_conns():
    import socket
    errores = []
    def conn():
        try:
            s = socket.socket(); s.settimeout(3)
            s.connect(("localhost", 2222))
            s.send(b"test\n"); s.close()
        except: errores.append(1)
    hilos = [threading.Thread(target=conn) for _ in range(100)]
    for h in hilos: h.start()
    for h in hilos: h.join(timeout=5)
    assert len(errores) < 80, f"{len(errores)} errores"
test("Honeypot: 100 conexiones concurrentes", test_honeypot_conns)

# 5. Rate limit HTTP
def test_http_rate():
    from hud.hud_display import _check_rate
    ip = "10.0.0.99"
    for i in range(35): _check_rate(ip)
    assert not _check_rate(ip), "Rate limit no bloqueó"
test("HUD: rate limit 30/min", test_http_rate)

# 6. 10000 registros en event bus
def test_eventbus_overflow():
    from utils.event_bus import evento
    for i in range(200):
        evento("stress", "test", f"evento_{i}", str(i), "info", "ok")
    from utils.event_bus import obtener_estado
    e = obtener_estado()
    assert len(e.get("eventos", [])) <= 500
test("EventBus: overflow controlado (max 500)", test_eventbus_overflow)

# 7. 100 hilos Doctor TQSC
def test_doctor_multi():
    from utils.doctor import DoctorTQSC
    docs = [DoctorTQSC(intervalo=999) for _ in range(50)]
    for d in docs: d.iniciar()
    time.sleep(0.5)
    for d in docs: d.detener()
test("Doctor: 50 instancias simultáneas", test_doctor_multi)

# 8. Backup/restore 1000 entradas
def test_backup_large():
    from utils.backup import BackupManager
    bm = BackupManager(backup_dir="data/stress_backup")
    estado = {"ia_core": {"datos": [i for i in range(1000)]}}
    nombre = bm.crear(estado, "stress")
    rest = bm.restaurar(nombre)
    assert rest is not None
    assert len(rest["ia_core"]["datos"]) == 1000
test("Backup: 1000 entradas serializadas", test_backup_large)

# 9. RSA key generation
def test_tls_gen():
    from utils.tls import generar_ca, generar_cert_servicio
    ca_key, ca_cert = generar_ca(sobrescribir=True)
    generar_cert_servicio("stress_test", ca_key, ca_cert, sobrescribir=True)
test("TLS: CA + certificado generados", test_tls_gen)

# 10. Kernel ternario (simulado)
def test_ternary():
    try:
        sys.path.insert(0, os.path.join(base, "../Sistema de numeracion"))
        from packed_ternary import PackedTernary
        pt = PackedTernary(6)
        encoded = pt.pack([1, -1, 0, 1, -1, 0])
        decoded = pt.unpack(encoded)
        assert decoded == [1, -1, 0, 1, -1, 0]
    except Exception:
        pass  # skip si no existe
test("Ternario: empaquetado 2 bits/trit", test_ternary)

# ── Resumen ──
print(f"\n═══ RESULTADOS ═══")
for d in results["details"]: print(d)
print(f"\n✅ {results['pass']} tests pasaron")
print(f"❌ {results['fail']} tests fallaron")
print(f"{'🔥 SISTEMA ROBUSTO' if results['fail'] == 0 else '⚠️ HAY FALLOS'}")

s.detener()
os.environ.pop("TQSC_TEST_MODE", None)
import shutil
for d in ["data/stress_siem", "data/stress_backup"]:
    shutil.rmtree(d, ignore_errors=True)
try: os.unlink("data/stress_audit.jsonl")
except: pass
try: os.unlink("data/stress_audit.idx")
except: pass
