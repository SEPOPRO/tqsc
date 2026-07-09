"""
TQSC v2.0 — TQSC World Model
Dataset de entrenamiento que cubre TODOS los 9 núcleos y sus 54+ subnúcleos.

Genera ~5000 muestras de comportamiento del sistema completo,
simulando estados normales y anómalos para cada subnúcleo.
"""
import json, math, random, secrets, hashlib
from pathlib import Path

random.seed(42)

# ── Feature space: 9 grupos, uno por núcleo ──────────────────

def generar_features_ia() -> dict:
    """Núcleo 1: IA Autoevolutiva (OctaRCQ-X8) — 18 subnúcleos."""
    n_octantes = random.randint(1, 8)
    return {
        "ia_n_octantes": n_octantes,
        "ia_n_hipotesis": random.randint(0, 20),
        "ia_confianza_prom": round(random.uniform(0, 1), 3),
        "ia_confianza_min": round(random.uniform(0, 0.5), 3),
        "ia_n_fuentes": random.randint(0, 10),
        "ia_errores": random.randint(0, 5),
        "ia_hipotesis_repetidas": random.randint(0, 1),
        "ia_confianza_cayendo": random.randint(0, 1),
        "ia_tasa_mutacion": round(random.uniform(0, 1), 3),
        "ia_n_patrones_unicos": random.randint(0, 50),
        "ia_entropia_adn": round(random.uniform(4, 8), 2),
        "ia_ghost_ocupado": round(random.uniform(0, 1), 2),
        "ia_loop_count": random.randint(0, 10),
        "ia_n_clones": random.randint(0, 8),
    }

def generar_features_defensa() -> dict:
    """Núcleo 2: Protección Física — 12 subnúcleos."""
    return {
        "def_cpu_promedio": round(random.uniform(0, 100), 1),
        "def_cpu_max": round(random.uniform(0, 100), 1),
        "def_mem_usada_mb": random.randint(100, 16000),
        "def_n_procesos": random.randint(50, 500),
        "def_n_procesos_nuevos": random.randint(0, 20),
        "def_temp_cpu": round(random.uniform(30, 100), 1),
        "def_cache_escritos_kb": random.randint(0, 10000),
        "def_entropia_opcode": round(random.uniform(0, 8), 2),
        "def_n_pids_verificados": random.randint(0, 100),
        "def_n_hotpatch": random.randint(0, 3),
        "def_anomalia_termica": random.randint(0, 1),
        "def_senal_syscall": random.randint(0, 1),
    }

def generar_features_blockchain() -> dict:
    """Núcleo 3: Blockchain — 7 subnúcleos."""
    return {
        "bc_nodos_activos": random.randint(1, 7),
        "bc_nodos_confiables": random.randint(0, 7),
        "bc_nodos_comprometidos": random.randint(0, 3),
        "bc_forks_detectados": random.randint(0, 5),
        "bc_reconsensos": random.randint(0, 3),
        "bc_desafios_activos": random.randint(0, 10),
        "bc_reputacion_min": round(random.uniform(0, 1), 2),
    }

def generar_features_cuanticas() -> dict:
    """Núcleo 4: ClassicCrypto — 5 subnúcleos."""
    return {
        "qc_confianza_firma": round(random.uniform(0, 1), 2),
        "qc_confianza_hash": round(random.uniform(0, 1), 2),
        "qc_n_errores_validacion": random.randint(0, 5),
        "qc_hay_firma": random.randint(0, 1),
        "qc_edad_evento_s": random.randint(0, 3600),
    }

def generar_features_honeypot() -> dict:
    """Núcleo 5: Honeypots — 5 subnúcleos."""
    return {
        "hp_conexiones_activas": random.randint(0, 50),
        "hp_conexiones_por_ip": random.randint(0, 10),
        "hp_n_sesiones_hoy": random.randint(0, 100),
        "hp_ultimo_tipo": random.choice(["brute-force", "scanner", "sqli", "xss", "desconocido"]),
        "hp_tasa_autenticacion": round(random.uniform(0, 1), 2),
    }

def generar_features_entropia() -> dict:
    """Núcleo 6: Entropy — 4 subnúcleos."""
    return {
        "en_entropia_actual": round(random.uniform(0.3, 1.0), 3),
        "en_baseline": round(random.uniform(0.5, 0.8), 3),
        "en_tendencia": random.choice(["estable", "creciente", "decreciente"]),
        "en_shield_activo": random.randint(0, 1),
        "en_dns_count": random.randint(0, 50),
        "en_volumen_red_mb": round(random.uniform(0, 100), 1),
    }

def generar_features_cortex() -> dict:
    """Núcleo 7: Cortex — supervisor."""
    return {
        "cx_ciclos_degenerativos": random.randint(0, 5),
        "cx_confianza_prom": round(random.uniform(0, 1), 2),
        "cx_errores_consecutivos": random.randint(0, 5),
        "cx_congelado": random.randint(0, 1),
    }

def generar_features_paz() -> dict:
    """Núcleo 8: ProtocoloPaz."""
    return {
        "pz_agentes_conocidos": random.randint(1, 10),
        "pz_agentes_confiables": random.randint(0, 10),
        "pz_mensajes_recibidos": random.randint(0, 100),
        "pz_firmas_invalidas": random.randint(0, 5),
    }

def generar_features_memoria() -> dict:
    """Núcleo 9: MemoriaEpisodica."""
    return {
        "me_n_recuerdos": random.randint(0, 100),
        "me_n_validos": random.randint(0, 100),
        "me_n_implantados": random.randint(0, 10),
        "me_tasa_veracidad": round(random.uniform(0.5, 1.0), 2),
    }


# ── Output targets: decisiones de cada núcleo ────────────────

def generar_targets(features: dict) -> dict:
    """Genera las decisiones esperadas de cada núcleo/subnúcleo
    basado en las features del sistema. Esto es el 'conocimiento'
    que el modelo debe aprender.
    
    Las reglas aquí son la VERSIÓN SIMPLIFICADA del comportamiento
    real de TQSC — el modelo aprende a imitar estas reglas,
    luego puede generalizar a casos no vistos.
    """
    t = {}

    # PatternInverter: tipo de ataque
    t["pi_tipo"] = 0  # normal
    hp_tipo = features.get("hp_ultimo_tipo", "normal")
    tipo_map = {"normal": 0, "brute-force": 1, "dictionary": 2, "scanner": 3,
                "exploit": 4, "sqli": 5, "xss": 6, "fuzzing": 7}
    t["pi_tipo"] = tipo_map.get(hp_tipo, 0)
    t["pi_accion"] = 0 if t["pi_tipo"] == 0 else (1 if t["pi_tipo"] <= 3 else 2)

    # PreImpactSynthesizer: severidad
    senales = 0
    if features.get("ia_errores", 0) > 3: senales += 1
    if features.get("def_cpu_promedio", 0) > 80: senales += 1
    if features.get("bc_nodos_comprometidos", 0) > 1: senales += 1
    if features.get("cx_ciclos_degenerativos", 0) > 2: senales += 1
    if features.get("en_entropia_actual", 0.5) < 0.4: senales += 1
    t["pi_severidad"] = min(senales, 5)

    # CognitiveLoopDetector: ¿está en loop?
    t["cl_loop"] = 1 if features.get("ia_loop_count", 0) > 5 else 0

    # IAJudicial: ¿acción aceptable?
    t["ij_aceptable"] = 0 if features.get("ia_errores", 0) > 4 else 1

    # Cortex: ¿congelar?
    t["cx_congelar"] = 1 if features.get("cx_ciclos_degenerativos", 0) >= 3 else 0

    # EntropyImpactEstimator: ¿anomalía?
    diff = abs(features.get("en_entropia_actual", 0.5) - features.get("en_baseline", 0.65))
    t["en_anomalia"] = 1 if diff > 0.15 else 0

    # OpcodeInterruptionEngine: ¿shellcode?
    t["oc_shellcode"] = 1 if features.get("def_entropia_opcode", 0) > 6.0 else 0

    # HeatMapDifferentialShield: ¿anomalía térmica?
    t["hm_anomalia"] = 1 if features.get("def_anomalia_termica", 0) == 1 else 0

    # CacheDisruptor: ¿necesita invalidación?
    t["cd_necesita"] = 1 if features.get("def_cache_escritos_kb", 0) > 1000 else 0

    # PIDSignature: ¿reflectivo?
    t["ps_reflectivo"] = 1 if features.get("def_n_hotpatch", 0) > 0 else 0

    # Memoria: ¿implantación detectada?
    t["me_implantacion"] = 1 if features.get("me_n_implantados", 0) > 3 else 0

    # Blockchain: ¿fork detectado?
    t["bc_fork"] = 1 if features.get("bc_forks_detectados", 0) > 0 else 0

    return t


# ── Feature vector plano (para el modelo) ──────────────────

def features_to_vector(features: dict) -> list[float]:
    """Convierte dict de features a vector numérico plano."""
    # Orden determinista
    keys_orden = sorted(features.keys())
    # One-hot para variables categóricas
    vec = []
    for k in keys_orden:
        v = features[k]
        if isinstance(v, str):
            # Categórica → expandir
            if k == "en_tendencia":
                for opt in ["estable", "creciente", "decreciente"]:
                    vec.append(1.0 if v == opt else 0.0)
            elif k == "hp_ultimo_tipo":
                for opt in ["normal", "brute-force", "scanner", "sqli", "xss", "desconocido"]:
                    vec.append(1.0 if v == opt else 0.0)
            else:
                vec.append(0.0)
        else:
            vec.append(float(v))
    return vec


def targets_to_vector(targets: dict) -> list[float]:
    """Convierte dict de targets a vector numérico plano."""
    keys_orden = sorted(targets.keys())
    return [float(targets[k]) for k in keys_orden]


# ── Generación del dataset completo ────────────────────────

def generar_muestra() -> tuple[list[float], list[float], dict]:
    """Genera una muestra completa: features + targets + metadatos."""
    f = {}
    f.update(generar_features_ia())
    f.update(generar_features_defensa())
    f.update(generar_features_blockchain())
    f.update(generar_features_cuanticas())
    f.update(generar_features_honeypot())
    f.update(generar_features_entropia())
    f.update(generar_features_cortex())
    f.update(generar_features_paz())
    f.update(generar_features_memoria())

    t = generar_targets(f)
    x = features_to_vector(f)
    y = targets_to_vector(t)
    return x, y, {"features": f, "targets": t}


def generar_dataset(n: int = 10000, ruido: float = 0.05) -> tuple[list, list, list]:
    """Genera dataset completo.
    
    Args:
        n: Número de muestras
        ruido: Proporción de muestras con ruido (targets aleatorios)
              para simular comportamiento impredecible del mundo real
    """
    X, Y, metadatos = [], [], []
    for _ in range(n):
        x, y, meta = generar_muestra()
        # Añadir ruido a algunos targets (comportamiento real no es 100% determinista)
        if random.random() < ruido:
            y = [random.random() for _ in y]
        X.append(x)
        Y.append(y)
        metadatos.append(meta)
    return X, Y, metadatos


# ── Guardar dataset ────────────────────────────────────────

if __name__ == "__main__":
    X, Y, meta = generar_dataset(10000, ruido=0.05)
    Path("data/ml").mkdir(parents=True, exist_ok=True)
    with open("data/ml/world_model_dataset.json", "w") as f:
        json.dump({
            "n_muestras": len(X),
            "n_features": len(X[0]),
            "n_targets": len(Y[0]),
            "features_orden": sorted(meta[0]["features"].keys()),
            "targets_orden": sorted(meta[0]["targets"].keys()),
            "datos": [{"x": X[i], "y": Y[i]} for i in range(len(X))],
        }, f, indent=2)
    print(f"World Model Dataset: {len(X)} muestras, {len(X[0])} features, {len(Y[0])} targets")
    print("Features:", len(X[0]))
    print("Targets:", len(Y[0]))
    print("\nOutput heads (núcleos):")
    for k in sorted(meta[0]["targets"].keys()):
        print(f"  {k}")
