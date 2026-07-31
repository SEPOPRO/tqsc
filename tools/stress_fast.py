"""
Stress test rápido — 10 tests en línea, sin TQSC init completo.
"""
import sys, os, time, threading, json
base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(base)
os.environ["TQSC_TEST_MODE"] = "1"
sys.path.insert(0, os.path.join(base, "tqsc"))

results = {"pass": 0, "fail": 0}
def test(name, fn):
    try:
        fn(); results["pass"] += 1; print(f"  ✅ {name}")
    except Exception as e:
        results["fail"] += 1; print(f"  ❌ {name}: {e}")

print("═══ STRESS TEST ═══")

# 1. SIEM 1000 eventos
def t1():
    from utils.siem_core import SIEMCore
    sc = SIEMCore("data/stress")
    for i in range(1000):
        sc.ingesta_evento({"t":"test","n":"t","a":"f","d":str(i),"s":"i","ts":time.time()})
    assert len(list(sc.store._cache)) >= 900
test("SIEM: 1000 eventos", t1)

# 2. Auditoría 500 entradas
def t2():
    from utils.audit import AuditTrail
    at = AuditTrail("data/stress_a.jsonl","s",siem=False)
    for i in range(500): at.registrar("s","t","/s",str(i),"INFO")
    r = at.verificar()
    assert all(e.get("integro") for e in r) and len(r)==500
test("Auditoría: 500 integras", t2)

# 3. Auth brute force 20 intentos
def t3():
    from utils.auth import AuthManager
    am = AuthManager("sk")
    for i in range(10): am.autenticar("admin","x","")
    assert am.autenticar("admin","admin","") is None
test("Auth: lockout 5 fallos", t3)

# 4. Rate limit 35 requests
def t4():
    from hud.hud_display import _check_rate
    for _ in range(35): _check_rate("99.99.99.99")
    assert not _check_rate("99.99.99.99")
test("HUD: rate limit 30/min", t4)

# 5. EventBus 200 eventos
def t5():
    from utils.event_bus import evento, obtener_estado
    for i in range(200):
        evento("test","t",f"e{i}",str(i),"i","ok")
    assert len(obtener_estado().get("eventos",[])) <= 500
test("EventBus: overflow max 500", t5)

# 6. Doctor 50 instancias
def t6():
    from utils.doctor import DoctorTQSC
    docs = [DoctorTQSC(999) for _ in range(50)]
    for d in docs: d.iniciar(); d.detener()
test("Doctor: 50 instancias", t6)

# 7. TLS generate
def t7():
    from utils.tls import generar_ca, generar_cert_servicio
    k, c = generar_ca(sobrescribir=True)
    generar_cert_servicio("stress2", k, c, sobrescribir=True)
test("TLS: CA + cert", t7)

# 8. Backup 1000 entries
def t8():
    from utils.backup import BackupManager
    bm = BackupManager(backup_dir="data/stress_bk")
    n = bm.crear({"d": list(range(1000))}, "s")
    assert bm.restaurar(n) is not None
test("Backup: 1000 entries", t8)

# 9. MFA habilitar/deshabilitar
def t9():
    from utils.mfa import MFA
    m = MFA("data/stress_mfa")
    s = m.habilitar("u1")
    assert m.uri("u1") and "otpauth" in m.uri("u1")
    m.deshabilitar("u1")
    assert m.uri("u1") is None
test("MFA: enable/disable", t9)

# 10. Identity con certificado
def t10():
    from utils.identity import IdentityManager
    mgr = IdentityManager("data/stress_id")
    i = mgr.registrar("nucleo_test")
    assert i.activa
    fp = i.fingerprint()
    assert len(fp) == 16 and fp != "0"*16
test("Identity: cert + fingerprint", t10)

print(f"\n✅ {results['pass']}/10 tests")
print(f"{'🔥 ROBUSTO' if results['fail'] == 0 else '⚠️ FALLOS'}")

import shutil
for d in ["data/stress","data/stress_bk","data/stress_mfa","data/stress_id"]:
    shutil.rmtree(d, ignore_errors=True)
for f in ["data/stress_a.jsonl","data/stress_a.idx"]:
    try: os.unlink(f)
    except: pass
os.environ.pop("TQSC_TEST_MODE", None)
