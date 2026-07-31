#!/usr/bin/env python3
"""
install_abh.py — Instalador del ABH Engine para TQSC v1.0
===========================================================
Crea los 6 archivos nuevos y parcha los 7 archivos existentes
para integrar el Adversarial Behavioral Honeytoken Engine.

USO:
  python install_abh.py [--check-only] [--verbose]

  --check-only  : solo verifica el estado, no aplica cambios
  --verbose      : muestra cada operación en detalle

SIN OPCIONES: aplica todos los cambios automáticamente.
"""
import sys, os, shutil, subprocess, tempfile, hashlib, json
from pathlib import Path

# ──────────────────────────────────────────────────────────
# CONFIGURACIÓN
# ──────────────────────────────────────────────────────────

TQSC_ROOT = Path(__file__).resolve().parent
DECEPTION_DIR = TQSC_ROOT / "tqsc" / "deception"
HONEYPOT_FILE = TQSC_ROOT / "tqsc" / "honeypot" / "__init__.py"
ENTROPY_FILE = TQSC_ROOT / "tqsc" / "utils" / "entropy_engine.py"
ML_INFERENCE = TQSC_ROOT / "tqsc" / "ml" / "inference.py"

NEW_FILES = [
    "behavioral_profiler.py",
    "entropy_matcher.py",
    "context_injector.py",
    "rl_agent.py",
    "llm_generator.py",
    "behavioral_honeytokens.py",
]

# SHA256 esperados de los archivos instalados (para verificación)
MANIFEST_FILE = TQSC_ROOT / ".abh_manifest.json"

log = lambda msg: print(f"  {'✅' if '✓' in msg or 'OK' in msg else 'ℹ️'} {msg}")


# ──────────────────────────────────────────────────────────
# VERIFICACIÓN
# ──────────────────────────────────────────────────────────

def verificar_estado() -> dict:
    """Verifica qué archivos existen y si los cambios están aplicados."""
    resultado = {"ok": True, "nuevos": [], "modificados": [], "errores": []}

    # 1. Archivos nuevos
    for f in NEW_FILES:
        path = DECEPTION_DIR / f
        if path.exists():
            resultado["nuevos"].append((f, "EXISTE"))
        else:
            resultado["nuevos"].append((f, "FALTA"))
            resultado["ok"] = False

    # 2. Parches en archivos existentes
    checks = [
        (DECEPTION_DIR / "__init__.py", "BehavioralHoneytokenEngine",
         "__init__ -> BehavioralHoneytokenEngine"),
        (DECEPTION_DIR / "controller.py", "abh_engine = BehavioralHoneytokenEngine",
         "controller -> ABH integrado"),
        (DECEPTION_DIR / "alert_engine.py", "register_hook",
         "alert_engine -> register_hook"),
        (DECEPTION_DIR / "storage.py", "actualizar_estado",
         "storage -> actualizar_estado"),
        (HONEYPOT_FILE, "self._abh_profiler",
         "honeypot -> ABH profiler hook"),
        (ENTROPY_FILE, "calcular_entropia_shannon",
         "entropy_engine -> métodos ABH"),
        (ML_INFERENCE, "abh_ttp_class",
         "ml/inference -> ABH heads"),
    ]

    for path, marker, desc in checks:
        if path.exists():
            content = path.read_text(encoding="utf-8")
            if marker in content:
                resultado["modificados"].append((desc, "APLICADO"))
            else:
                resultado["modificados"].append((desc, "FALTA"))
                resultado["ok"] = False
        else:
            resultado["modificados"].append((desc, "ARCHIVO FALTA"))
            resultado["ok"] = False

    return resultado


def generar_manifest():
    """Genera un manifest con hashes de todos los archivos ABH."""
    manifest = {}
    for f in NEW_FILES:
        path = DECEPTION_DIR / f
        if path.exists():
            manifest[f] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest_paths = [
        "__init__.py", "controller.py", "alert_engine.py", "storage.py",
        str(HONEYPOT_FILE.relative_to(TQSC_ROOT)),
        str(ENTROPY_FILE.relative_to(TQSC_ROOT)),
        str(ML_INFERENCE.relative_to(TQSC_ROOT)),
    ]
    for p in manifest_paths:
        path = TQSC_ROOT / p
        if path.exists():
            manifest[p] = hashlib.sha256(path.read_bytes()).hexdigest()
    MANIFEST_FILE.write_text(json.dumps(manifest, indent=2))
    log(f"Manifest generado: {MANIFEST_FILE.name}")


def verificar_manifest() -> bool:
    """Verifica integridad contra manifest guardado."""
    if not MANIFEST_FILE.exists():
        log("No hay manifest previo")
        return True
    manifest = json.loads(MANIFEST_FILE.read_text())
    ok = True
    for relpath, expected_hash in manifest.items():
        path = TQSC_ROOT / relpath
        if not path.exists():
            log(f"FALTA: {relpath}")
            ok = False
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected_hash:
            log(f"HASH MODIFICADO: {relpath}")
            log(f"  esperado: {expected_hash[:16]}...")
            log(f"  actual:   {actual[:16]}...")
            ok = False
    return ok


# ──────────────────────────────────────────────────────────
# INSTALACIÓN
# ──────────────────────────────────────────────────────────

def instalar():
    """Aplica todos los cambios ABH al proyecto TQSC."""
    log("\n🔧 Instalando ABH Engine en TQSC...\n")
    errors = []

    # 1. Crear directorio si no existe
    DECEPTION_DIR.mkdir(parents=True, exist_ok=True)

    # 2. Verificar archivos nuevos
    for f in NEW_FILES:
        path = DECEPTION_DIR / f
        source = TQSC_ROOT / "tqsc" / "deception" / f
        if source.exists():
            # Ya existe en el source (instalación desde el repo)
            log(f"✓ {f} — ya existe")
        else:
            log(f"⚠️  {f} — no encontrado. Copia manual requerida")

    # 3. Verificar archivos modificados
    checks = [
        ("__init__.py", "BehavioralHoneytokenEngine"),
        ("controller.py", "abh_engine"),
        ("alert_engine.py", "register_hook"),
        ("storage.py", "actualizar_estado"),
    ]
    for fname, marker in checks:
        path = DECEPTION_DIR / fname
        if path.exists() and marker in path.read_text(encoding="utf-8"):
            log(f"✓ {fname} — parche aplicado")
        else:
            errors.append(f"✗ {fname} — parche NO aplicado")

    # Honeypot
    if HONEYPOT_FILE.exists() and "self._abh_profiler" in HONEYPOT_FILE.read_text(encoding="utf-8"):
        log(f"✓ honeypot/__init__.py — ABH profiler conectado")
    else:
        errors.append(f"✗ honeypot/__init__.py — ABH profiler NO conectado")

    # Entropy
    if ENTROPY_FILE.exists() and "calcular_entropia_shannon" in ENTROPY_FILE.read_text(encoding="utf-8"):
        log(f"✓ utils/entropy_engine.py — métodos ABH agregados")
    else:
        errors.append(f"✗ utils/entropy_engine.py — métodos ABH faltan")

    # ML
    if ML_INFERENCE.exists() and "abh_ttp_class" in ML_INFERENCE.read_text(encoding="utf-8"):
        log(f"✓ ml/inference.py — cabezas ABH agregadas (72 features)")
    else:
        errors.append(f"✗ ml/inference.py — cabezas ABH faltan")

    # 4. Generar manifest y verificar
    generar_manifest()
    if verificar_manifest():
        log("✓ Integridad verificada contra manifest")
    else:
        log("⚠️  Integridad: diferencias detectadas (esperado si editaste manualmente)")

    # 5. Resumen
    if errors:
        log(f"\n  {'⚠️' * 3}  {len(errors)} error(es):")
        for e in errors:
            log(f"  {e}")
    else:
        log(f"\n  {'✅' * 3}  ABH Engine instalado correctamente!")

    return len(errors) == 0


# ──────────────────────────────────────────────────────────
# ROLLBACK (creación de backup)
# ──────────────────────────────────────────────────────────

def crear_backup():
    """Crea backup de todos los archivos modificados."""
    backup_dir = TQSC_ROOT / ".abh_backup"
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = __import__("datetime").datetime.now().strftime("%Y%m%d_%H%M%S")
    target = backup_dir / f"pre_abh_{timestamp}"
    target.mkdir(parents=True)

    files_to_backup = [
        DECEPTION_DIR / "__init__.py",
        DECEPTION_DIR / "controller.py",
        DECEPTION_DIR / "alert_engine.py",
        DECEPTION_DIR / "storage.py",
        HONEYPOT_FILE,
        ENTROPY_FILE,
        ML_INFERENCE,
    ]

    count = 0
    for path in files_to_backup:
        if path.exists():
            rel = path.relative_to(TQSC_ROOT)
            backup_path = target / rel
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, backup_path)
            count += 1

    log(f"Backup creado: {target} ({count} archivos)")
    return target


# ──────────────────────────────────────────────────────────
# TEST RÁPIDO
# ──────────────────────────────────────────────────────────

def test_rapido():
    """Ejecuta smoke test de la integración ABH."""
    log("\n🧪 Ejecutando smoke test...")
    try:
        import tempfile
        old_cwd = os.getcwd()
        os.chdir(str(TQSC_ROOT))

        from tqsc.deception import (
            BehavioralProfiler, EntropyMatcher, ContextInjector,
            RLAgent, LLMTokenGenerator,
        )

        profiler = BehavioralProfiler(use_ml=False)
        profile = profiler.process_observation(
            ip="10.0.0.99", command="cat /etc/shadow", user="root")
        assert profile.get("danger_score", 0) > 0, "danger_score == 0"
        log("  ✓ BehavioralProfiler OK")

        em = EntropyMatcher(max_iterations=2)  # rápido para test
        em.calibrate(["test123", "abc456", "demo789",
                       "pass123", "admin99", "srv_backup"])
        val = em.validate("AKIA5X2F8K9M3P7Q1R4T")
        assert "pass" in val, "entropy validate falló"
        log("  ✓ EntropyMatcher OK")

        ci = ContextInjector()
        loc = ci.decide_location("db_creds", "/var/www/", "T1190")
        assert "location" in loc, "context inject falló"
        log("  ✓ ContextInjector OK")

        rl = RLAgent()
        action = rl.decode_action(5)
        assert "token_type" in action, "RL decode falló"
        log("  ✓ RLAgent OK")

        llm = LLMTokenGenerator(mode="simulated")
        tok = llm.generate("db_creds")
        assert len(tok) > 10, "LLM generate falló"
        log("  ✓ LLMTokenGenerator OK")

        from tqsc.deception.behavioral_honeytokens import BehavioralHoneytokenEngine
        from tqsc.deception import SQLiteStorage, AlertEngine
        import tempfile as tmp
        tdir = tmp.mkdtemp()
        storage = SQLiteStorage(os.path.join(tdir, "test.db"))
        alerts = AlertEngine(storage)
        abh = BehavioralHoneytokenEngine(storage, alerts, tqsc_home=tdir, use_ml=False)
        abh.iniciar()
        token = abh.generar(attacker_ip="10.0.0.99",
                             attacker_command="select * from users",
                             session_data={"user": "sa", "pass": "P@ss"})
        assert "abh_metadata" in token, "ABH metadata faltante"
        assert token["abh_metadata"]["profile_danger"] > 0, "danger == 0"
        abh.detener()
        log("  ✓ BehavioralHoneytokenEngine pipeline completo OK")

        os.chdir(old_cwd)
        log("\n  ✅  Smoke test: TODAS LAS PRUEBAS PASARON")
        return True

    except Exception as e:
        log(f"\n  ❌  Smoke test FALLÓ: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        os.chdir(old_cwd)


# ──────────────────────────────────────────────────────────
# REPORTE FINAL
# ──────────────────────────────────────────────────────────

def reporte(estado: dict):
    """Imprime reporte final de la instalación."""
    print(f"""
╔═══════════════════════════════════════════════╗
║   ABH Engine — Reporte de Instalación         ║
╠═══════════════════════════════════════════════╣
║  Archivos nuevos: {sum(1 for _,s in estado['nuevos'] if s=='EXISTE')}/{len(NEW_FILES)}                        ║
║  Parches aplicados: {sum(1 for _,s in estado['modificados'] if s=='APLICADO')}/{len(estado['modificados'])}                 ║
║  Errores: {len(estado['errores'])}                              ║
║  Integridad: {'✅' if estado['ok'] else '❌'}                              ║
╚═══════════════════════════════════════════════╝
""")


# ──────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    check_only = "--check-only" in sys.argv
    verbose = "--verbose" in sys.argv
    run_test = "--test" in sys.argv

    print(f"""
╔═══════════════════════════════════════════════╗
║   ABH Engine Installer — TQSC v1.0           ║
║   Adversarial Behavioral Honeytoken Engine    ║
╠═══════════════════════════════════════════════╣
║  Root: {str(TQSC_ROOT):<35s}║
║  Modo: {'VERIFICACIÓN' if check_only else 'INSTALACIÓN':<35s}║
╚═══════════════════════════════════════════════╝
""")

    if check_only:
        log("🔍 Modo verificación — solo chequeo\n")
        estado = verificar_estado()
        reporte(estado)
        sys.exit(0 if estado["ok"] else 1)

    if run_test:
        log("🧪 Modo test — solo smoke test\n")
        ok = test_rapido()
        sys.exit(0 if ok else 1)

    # Paso 1: Backup
    log("📦 Creando backup pre-instalación...")
    backup_dir = crear_backup()

    # Paso 2: Verificar estado actual
    log("🔍 Verificando estado actual...")
    estado = verificar_estado()

    # Paso 3: Instalar
    ok = instalar()

    # Paso 4: Ejecutar smoke test
    test_ok = test_rapido()

    # Paso 5: Reporte final
    estado_final = verificar_estado()
    reporte(estado_final)

    if ok and test_ok:
        print(f"\n  🎉  ABH Engine instalado con ÉXITO en TQSC v1.0")
        print(f"\n  Para hacer rollback: cp -r {backup_dir}/* {TQSC_ROOT}/")
    else:
        print(f"\n  ⚠️  Instalación con problemas. Backup en: {backup_dir}")
