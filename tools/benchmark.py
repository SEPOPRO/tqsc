import sys, os, time, json, threading, subprocess, gc
from datetime import datetime

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(BASE)
os.environ["TQSC_TEST_MODE"] = "1"
sys.path.insert(0, os.path.join(BASE, "tqsc"))

results = {}

def medir(nombre, fn, *args, **kwargs):
    gc.collect()
    inicio = time.perf_counter()
    resultado = fn(*args, **kwargs)
    fin = time.perf_counter()
    results[nombre] = {"tiempo_ms": round((fin - inicio) * 1000, 2)}
    return resultado

def bench_siem_throughput():
    from utils.siem_core import SIEMCore
    sc = SIEMCore("data/bench_siem")
    eventos = [{"t": "bench", "n": "test", "a": "t", "d": str(i), "s": "info", "ts": time.time()} for i in range(5000)]
    inicio = time.perf_counter()
    for e in eventos: sc.ingesta_evento(e)
    fin = time.perf_counter()
    t = fin - inicio
    results["siem_throughput"] = {"eventos": 5000, "tiempo_s": round(t,3), "eventos_seg": round(5000/t,0)}
    import shutil; shutil.rmtree("data/bench_siem", ignore_errors=True)

def bench_audit_chain():
    from utils.audit import AuditTrail
    at = AuditTrail("data/bench_audit.jsonl", "bench", siem=False)
    inicio = time.perf_counter()
    for i in range(1000): at.registrar("bench", "tester", "/test", str(i), "INFO")
    fin = time.perf_counter()
    t = fin - inicio
    ver = at.verificar()
    results["audit_chain"] = {"entradas": 1000, "tiempo_s": round(t,3), "entradas_seg": round(1000/t,0), "integridad": f"{sum(1 for e in ver if e.get('integro'))}/{len(ver)}"}
    os.unlink("data/bench_audit.jsonl")
    try: os.unlink("data/bench_audit.idx")
    except: pass

def bench_auth_rate():
    from utils.auth import AuthManager
    am = AuthManager("bench-key")
    inicio = time.perf_counter()
    for i in range(200): am.verificar(am.autenticar("admin", "admin", "") or "")
    fin = time.perf_counter()
    results["auth_throughput"] = {"autenticaciones": 200, "tiempo_s": round(fin-inicio,3), "auth_seg": round(200/(fin-inicio),0)}

def bench_mfa():
    from utils.mfa import MFA
    mfa = MFA("data/bench_mfa")
    t = time.perf_counter()
    for _ in range(100): mfa.habilitar("test")
    t_enable = (time.perf_counter() - t) * 1000 / 100
    t = time.perf_counter()
    for _ in range(100): mfa.deshabilitar("test")
    t_disable = (time.perf_counter() - t) * 1000 / 100
    results["mfa"] = {"habilitar_ms": round(t_enable,3), "deshabilitar_ms": round(t_disable,3)}
    import shutil; shutil.rmtree("data/bench_mfa", ignore_errors=True)

def bench_hud_rate_limit():
    from hud.hud_display import _check_rate
    tiempos = []
    for _ in range(100):
        inicio = time.perf_counter()
        _check_rate("10.0.0.1")
        tiempos.append((time.perf_counter() - inicio) * 1000)
    results["hud_rate_limit"] = {"llamadas": 100, "promedio_ms": round(sum(tiempos)/len(tiempos), 4)}

def bench_event_bus():
    from utils.event_bus import evento
    inicio = time.perf_counter()
    for i in range(1000): evento("bench","test",f"e{i}",str(i),"info","ok")
    fin = time.perf_counter()
    results["event_bus"] = {"eventos": 1000, "tiempo_s": round(fin-inicio,3), "eventos_seg": round(1000/(fin-inicio),0)}

def bench_crypto():
    from classic_crypto import ClassicCryptoCore
    cc = ClassicCryptoCore()
    data = b"A" * 1024
    t_enc = []
    for _ in range(100):
        inicio = time.perf_counter()
        cc.cifrador.cifrar(data)
        t_enc.append((time.perf_counter() - inicio) * 1000)
    t_dec = []
    for _ in range(100):
        ct = cc.cifrador.cifrar(data)
        inicio = time.perf_counter()
        cc.cifrador.descifrar(ct)
        t_dec.append((time.perf_counter() - inicio) * 1000)
    results["crypto"] = {"cifrado_1kb_ms": round(sum(t_enc)/len(t_enc),3), "descifrado_1kb_ms": round(sum(t_dec)/len(t_dec),3)}

def bench_siem_correlation():
    from utils.siem_core import SIEMCore
    sc = SIEMCore("data/bench_corr")
    for i in range(100):
        sc.ingesta_evento({"t":"test","n":"honeypot","a":"ataque","d":f"login {i}","s":"crit","ts":time.time()})
    inicio = time.perf_counter()
    for _ in range(10): sc.correlar()
    fin = time.perf_counter()
    results["siem_correlacion"] = {"100_evts_10_rondas_ms": round((fin-inicio)*1000/10, 2)}
    import shutil; shutil.rmtree("data/bench_corr", ignore_errors=True)

def medir_memoria():
    try:
        import psutil
        p = psutil.Process()
        reposo = p.memory_info().rss / 1024 / 1024
        _ = [i**2 for i in range(100000)]
        carga = p.memory_info().rss / 1024 / 1024
        results["memoria"] = {"reposo_mb": round(reposo,1), "carga_mb": round(carga,1)}
    except ImportError:
        results["memoria"] = {"error": "psutil no disponible"}


if __name__ == "__main__":
    print("═══ BENCHMARK TQSC ═══\n")
    bench_siem_throughput()
    bench_audit_chain()
    bench_auth_rate()
    bench_mfa()
    bench_hud_rate_limit()
    bench_event_bus()
    bench_crypto()
    bench_siem_correlation()
    medir_memoria()

    for k, v in sorted(results.items()):
        if isinstance(v, dict):
            vals = " | ".join(f"{sk}: {sv}" for sk, sv in v.items())
            print(f"  {k:25s} → {vals}")

    os.makedirs("data", exist_ok=True)
    with open("data/benchmark_results.json", "w") as f:
        json.dump({"timestamp": datetime.utcnow().isoformat()+"Z", "resultados": results}, f, indent=2)
    print(f"\nResultados guardados en data/benchmark_results.json")
    os.environ.pop("TQSC_TEST_MODE", None)
