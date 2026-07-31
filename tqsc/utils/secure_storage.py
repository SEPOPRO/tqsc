"""
TQSC v2.0 — SecureStorage
Cifrado AES-256-GCM transparente para todos los logs/data en disco.
Reemplaza json.dump + open() en todos los módulos que persisten datos.
"""
import json, logging, base64
from pathlib import Path
from typing import Any, Optional

LOG = logging.getLogger("tqsc.secure_storage")

# Singleton del cifrador — inicializado lazy
_CIFRADOR = None
_KEY_MANAGER = None


def _inicializar(data_dir: str = "data"):
    global _CIFRADOR, _KEY_MANAGER
    if _CIFRADOR is None:
        from classic_crypto import KeyManager, CifradorAES
        _KEY_MANAGER = KeyManager(data_dir=data_dir)
        _CIFRADOR = CifradorAES(_KEY_MANAGER, contexto="secure_storage")
        # Verificar integridad: si la clave maestra fue modificada, falla ruidosamente
        if not _KEY_MANAGER._verificar_integridad():
            _CIFRADOR = None
            raise RuntimeError("SecureStorage: clave maestra comprometida")
    return _CIFRADOR


def write(path: Path, datos: Any):
    """Escribe datos cifrados a disco (JSON + AES-256-GCM)."""
    try:
        cifrador = _inicializar(str(path.parent))
        raw = json.dumps(datos, ensure_ascii=False, default=str).encode()
        ct = cifrador.cifrar(raw)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(ct)
    except Exception as e:
        LOG.error("SecureStorage: error escribiendo %s: %s", path.name, e)
        raise


def read(path: Path) -> Optional[Any]:
    """Lee y descifra datos desde disco."""
    try:
        if not path.exists():
            return None
        cifrador = _inicializar(str(path.parent))
        ct = path.read_bytes()
        raw = cifrador.descifrar(ct)
        return json.loads(raw)
    except Exception as e:
        LOG.error("SecureStorage: error leyendo %s: %s", path.name, e)
        return None


def append(path: Path, datos: Any):
    """Añade un registro cifrado a un archivo (JSONL cifrado)."""
    try:
        cifrador = _inicializar(str(path.parent))
        raw = json.dumps(datos, ensure_ascii=False, default=str).encode()
        ct = cifrador.cifrar(raw)
        b64_ct = base64.b64encode(ct)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "ab") as f:
            f.write(b64_ct + b"\n")
    except Exception as e:
        LOG.error("SecureStorage: error appending %s: %s", path.name, e)


def read_all(path: Path) -> list[Any]:
    """Lee todos los registros de un JSONL cifrado."""
    try:
        if not path.exists():
            return []
        cifrador = _inicializar(str(path.parent))
        resultados = []
        with open(path, "rb") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                ct = base64.b64decode(line)
                raw = cifrador.descifrar(ct)
                resultados.append(json.loads(raw))
        return resultados
    except Exception as e:
        LOG.error("SecureStorage: error read_all %s: %s", path.name, e)
        return []


def migrar_plano_a_cifrado(path: Path):
    """Migra un archivo JSON plano a cifrado (una vez)."""
    if path.exists() and path.stat().st_size > 0:
        try:
            # Intentar leer como cifrado primero
            data = read(path)
            if data is not None:
                return  # ya está cifrado
        except Exception:
            pass
        # Leer como plano
        try:
            with open(path) as f:
                data = json.load(f)
            write(path, data)
            LOG.info("SecureStorage: migrado %s a cifrado", path.name)
        except Exception:
            pass
