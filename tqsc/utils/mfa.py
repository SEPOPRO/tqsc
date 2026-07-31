"""
tqsc/utils/mfa.py — MFA con TOTP (RFC 6238) para PCI DSS §8.2.
Secretos cifrados con AES-256-GCM (no XOR).
"""
import hmac, hashlib, struct, time, base64, os, logging, json
from pathlib import Path
from typing import Optional

LOG = logging.getLogger("tqsc.mfa")
TOTP_STEP = 30; TOTP_DIGITS = 6; TOTP_WINDOW = 1


def _generar_secreto() -> str:
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def _totp(secreto: str, timestamp: Optional[int] = None) -> str:
    if timestamp is None: timestamp = int(time.time())
    msg = struct.pack(">Q", timestamp // TOTP_STEP)
    padding = (8 - len(secreto) % 8) % 8
    key = base64.b32decode(secreto.upper() + "=" * padding)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    codigo = ((h[offset] & 0x7F) << 24 | (h[offset + 1] & 0xFF) << 16 |
              (h[offset + 2] & 0xFF) << 8 | (h[offset + 3] & 0xFF))
    return f"{codigo % (10 ** TOTP_DIGITS):0{TOTP_DIGITS}d}"


def _uri(secreto: str, usuario: str, emisor: str = "TQSC") -> str:
    return (f"otpauth://totp/{emisor}:{usuario}?secret={secreto}"
            f"&issuer={emisor}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP}")


def _cifrar_aes(texto_plano: str) -> str:
    """Cifra con AES-256-GCM vía ClassicCryptoCore."""
    try:
        from utils.secure_storage import SecureStorage
        ss = SecureStorage("data")
        return ss._cifrar(texto_plano.encode()).hex()
    except Exception as e:
        raise RuntimeError("MFA secrets cannot be stored securely.") from e


def _descifrar_aes(hex_data: str) -> str:
    """Descifra con AES-256-GCM vía ClassicCryptoCore."""
    try:
        from utils.secure_storage import SecureStorage
        ss = SecureStorage("data")
        raw = bytes.fromhex(hex_data)
        return ss._descifrar(raw).decode()
    except Exception as e:
        raise RuntimeError("MFA secrets cannot be stored securely.") from e


class MFA:
    def __init__(self, data_dir: str = "data"):
        self._ruta = Path(data_dir) / "mfa_secrets.json"
        self._ruta.parent.mkdir(parents=True, exist_ok=True)
        self._secretos: dict[str, str] = {}
        self._cargar()

    def _cargar(self):
        if not self._ruta.exists():
            return
        try:
            data = json.loads(self._ruta.read_text())
            if not isinstance(data, dict):
                self._secretos = {}; return
            self._secretos = {}
            for user, val in data.items():
                if isinstance(val, str) and len(val) > 20 and all(c in "0123456789abcdef" for c in val):
                    self._secretos[user] = _descifrar_aes(val)
                else:
                    self._secretos[user] = val
        except (json.JSONDecodeError, OSError):
            self._secretos = {}

    def _guardar(self):
        encrypted = {u: _cifrar_aes(s) for u, s in self._secretos.items()}
        self._ruta.write_text(json.dumps(encrypted, indent=2))

    def habilitar(self, usuario: str) -> str:
        secreto = _generar_secreto()
        self._secretos[usuario] = secreto
        self._guardar()
        LOG.info("MFA habilitado para %s", usuario)
        return secreto

    def deshabilitar(self, usuario: str):
        self._secretos.pop(usuario, None)
        self._guardar()

    def uri(self, usuario: str, emisor: str = "TQSC") -> Optional[str]:
        s = self._secretos.get(usuario)
        return _uri(s, usuario, emisor) if s else None

    def verificar(self, usuario: str, codigo: str) -> bool:
        secreto = self._secretos.get(usuario)
        if not secreto:
            return True
        ahora = int(time.time())
        for v in range(-TOTP_WINDOW, TOTP_WINDOW + 1):
            if hmac.compare_digest(_totp(secreto, ahora + v * TOTP_STEP), codigo):
                return True
        LOG.warning("MFA: código inválido para %s", usuario)
        return False

    def estado(self, usuario: str) -> dict:
        return {"habilitado": usuario in self._secretos, "uri": self.uri(usuario)}


_mfa: Optional[MFA] = None
def obtener_mfa() -> MFA:
    global _mfa
    if _mfa is None:
        _mfa = MFA(os.environ.get("TQSC_HOME", "data"))
    return _mfa
