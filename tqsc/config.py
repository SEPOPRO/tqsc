"""
TQSC v1.0 — Configuración global del sistema.
"""
import os
from pathlib import Path

# ── Rutas ────────────────────────────────────
BASE_DIR = Path(__file__).parent
TQSC_HOME = os.environ.get("TQSC_HOME", "")
if TQSC_HOME:
    DATA_DIR = Path(TQSC_HOME)
else:
    DATA_DIR = BASE_DIR / "data"
LOG_DIR = DATA_DIR / "logs"
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# ── Nodos blockchain ─────────────────────────
import hashlib
DEFAULT_NODOS = {f"Nodo_{c}": hashlib.sha256(f"tqsc_nodo_{c}".encode()).hexdigest()[:16] for c in "ABCDEFG"}

# ── Umbrales de defensa ──────────────────────
HPA_TENSION_MAX = 0.45
HPA_TENSION_MAX_CODIGO = 0.80
MEA_ENTROPIA_MIN = 0.3

# ── Núcleo IA ────────────────────────────────
OCTA_NUCLEOS = 8
SHADOW_SYNC_INTERVAL = 60  # segundos
LOOP_DETECTOR_MAX_IDENTICOS = 2

# ── Validación cuántica ──────────────────────
VERACIDAD_MIN = 0.85
ENTROPY_BASELINE = 0.68
ENTROPY_TOLERANCIA = 0.15

# ── Honeypot ─────────────────────────────────
HONEYPOT_PUERTO = 2222
