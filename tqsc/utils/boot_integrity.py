"""
TQSC v2.0 — Boot Integrity (auto-verificado).
Verifica todo .py excepto sí mismo. Si detecta manipulación, NO arranca.
"""
import hashlib, hmac, json, os, logging, secrets, sys
from pathlib import Path
from typing import Optional

LOG = logging.getLogger("tqsc.boot")
EXCLUIR = {"__pycache__", ".git", ".master_key", "reputacion.json",
           "*.jsonl", "*.log", "*.pid"}

_CLAVE_RUTA = None; _CLAVE = None


def _inicializar(base_dir: str = None) -> tuple[Path, bytes]:
    global _CLAVE_RUTA, _CLAVE
    if base_dir is None: base_dir = Path(__file__).parent.parent
    base = Path(base_dir)
    if not _CLAVE_RUTA: _CLAVE_RUTA = base / "data" / ".boot_key"
    if not _CLAVE:
        try:
            _CLAVE = _CLAVE_RUTA.read_bytes()[:32]
        except FileNotFoundError:
            _CLAVE = secrets.token_bytes(32); _CLAVE_RUTA.parent.mkdir(parents=True, exist_ok=True)
            _CLAVE_RUTA.write_bytes(_CLAVE)
            try:
                os.chmod(_CLAVE_RUTA, 0o600)
            except Exception:
                pass
    return base, _CLAVE


def _listar_python(base: Path) -> list[Path]:
    archivos = []
    for root, dirs, files in os.walk(base):
        dirs[:] = [d for d in dirs if d not in EXCLUIR and not d.startswith(".")]
        for f in files:
            if f.endswith(".py") and "boot_integrity" not in f:
                archivos.append(Path(root) / f)
    return sorted(archivos)


def _fingerprint(archivo: Path, clave: bytes) -> str:
    contenido = archivo.read_bytes()
    h = hashlib.sha256(contenido).hexdigest()
    path_rel = str(archivo.relative_to(archivo.anchor))
    return hmac.new(clave, f"{path_rel}:{h}".encode(), hashlib.sha256).hexdigest()[:16]


def generar_huella(base_dir: str = None) -> dict:
    """Genera fingerprint de todos los .py excepto sí mismo."""
    base, clave = _inicializar(base_dir)
    archivos = _listar_python(base)
    fingerprint = {}
    for a in archivos:
        try: fingerprint[a.name] = _fingerprint(a, clave)
        except Exception as e: LOG.warning("Boot: error leyendo %s: %s", a, e)
    ruta = base / "data" / ".boot_fingerprint.json"
    with open(ruta, "w") as f:
        json.dump({"fingerprints": fingerprint, "total": len(fingerprint),
                   "generado": __import__("time").time()}, f, indent=4)
    LOG.info("Boot: huella generada — %d archivos", len(fingerprint))
    return fingerprint


def verificar(base_dir: str = None) -> tuple[bool, list[str]]:
    """Verifica integridad al arranque. No se verifica a sí mismo."""
    base, clave = _inicializar(base_dir)
    ruta_fp = base / "data" / ".boot_fingerprint.json"
    if not ruta_fp.exists():
        LOG.warning("Boot: primer arranque — generando huella")
        generar_huella(base_dir); return True, []
    with open(ruta_fp) as f: guardado = json.load(f)
    archivos = _listar_python(base)
    ok = True; modificados = []
    for a in archivos:
        try:
            esperado = guardado.get("fingerprints", {}).get(a.name)
            if esperado is None:
                LOG.warning("Boot: archivo NUEVO: %s", a.name)
                modificados.append(f"[NUEVO] {a.name}"); ok = False; continue
            actual = _fingerprint(a, clave)
            if not hmac.compare_digest(esperado, actual):
                LOG.critical("Boot: ARCHIVO MODIFICADO: %s", a.name)
                modificados.append(f"[MODIFICADO] {a.name}"); ok = False
        except Exception as e:
            modificados.append(f"[ERROR] {a.name}: {e}"); ok = False
    if not ok:
        for m in modificados: LOG.critical("  %s", m)
        LOG.critical("Boot: INTEGRIDAD COMPROMETIDA — negando arranque")
    return ok, modificados


def regenerar(base_dir: str = None):
    LOG.warning("Boot: regenerando huella (actualización legítima)")
    return generar_huella(base_dir)
