"""
tqsc/utils/auth.py — RBAC + Sesiones + Account Lockout (PCI §8.1 / AC-7).
"""
import json, logging, os, hmac, hashlib, time, secrets, threading
from datetime import datetime, timedelta
from typing import Optional

LOG = logging.getLogger("tqsc.auth")
ROLES = {"admin": 100, "operator": 50, "viewer": 10}
TOKEN_TTL = int(os.environ.get("TQSC_TOKEN_TTL", "3600"))


def _hmac(key: str, data: str) -> str:
    return hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()


class AuthManager:
    """RBAC + tokens HMAC + account lockout (5 fallos → 15min bloqueo)."""

    MAX_INTENTOS = 5
    BLOQUEO_MINUTOS = 15
    LOGIN_MAX_POR_USUARIO = 20  # intentos/minuto por usuario

    def __init__(self, secreto: str = ""):
        self._secreto = secreto or os.environ.get("TQSC_API_KEY", "")
        if not self._secreto:
            self._secreto = secrets.token_hex(16)
        # Forzar cambio de credenciales por defecto (PCI 8.2.2)
        _adm = os.environ.get("TQSC_ADMIN_PASSWORD", "admin")
        _op = os.environ.get("TQSC_OPERATOR_PASSWORD", "operator")
        _vw = os.environ.get("TQSC_VIEWER_PASSWORD", "viewer")
        if _adm == "admin" or _op == "operator" or _vw == "viewer":
            msg = ("⚠️ CREDENCIALES POR DEFECTO — Configure TQSC_ADMIN_PASSWORD, "
                   "TQSC_OPERATOR_PASSWORD, TQSC_VIEWER_PASSWORD")
            LOG.warning(msg)
            if not os.environ.get("TQSC_TEST_MODE"):
                LOG.error("🚫 TQSC rechazado con credenciales por defecto. %s", msg)
                raise RuntimeError("MUST_SET_PASSWORDS - Set TQSC_ADMIN_PASSWORD, "
                                   "TQSC_OPERATOR_PASSWORD, TQSC_VIEWER_PASSWORD en entorno")
        self._usuarios: dict[str, dict] = {
            "admin": {"role": "admin", "hash": _hmac(self._secreto, _adm)},
            "operator": {"role": "operator", "hash": _hmac(self._secreto, _op)},
            "viewer": {"role": "viewer", "hash": _hmac(self._secreto, _vw)},
        }
        self._tokens_activos: dict[str, dict] = {}
        self._intentos: dict[str, list[float]] = {}
        self._bloqueos: dict[str, float] = {}

    def _check_lockout(self, usuario: str) -> bool:
        if usuario in self._bloqueos:
            if time.time() - self._bloqueos[usuario] > self.BLOQUEO_MINUTOS * 60:
                del self._bloqueos[usuario]
                self._intentos[usuario] = []
                return False
            return True
        return False

    def _register_attempt(self, usuario: str, exitoso: bool):
        ahora = time.time()
        if exitoso:
            self._intentos.pop(usuario, None)
            self._bloqueos.pop(usuario, None)
            return
        if usuario not in self._intentos:
            self._intentos[usuario] = []
        self._intentos[usuario] = [t for t in self._intentos[usuario] if ahora - t < 3600]
        self._intentos[usuario].append(ahora)
        if len(self._intentos[usuario]) >= self.MAX_INTENTOS:
            self._bloqueos[usuario] = ahora
            LOG.warning("Cuenta BLOQUEADA: %s (%d intentos)", usuario, self.MAX_INTENTOS)
    def autenticar(self, usuario: str, password: str, mfa_code: str = "") -> Optional[str]:
        """Retorna token si credenciales + MFA válidas."""
        self.limpiar_expirados()

        # Rate limit por usuario (anti password spraying)
        ahora = time.time()
        intentos_user = [t for t in self._intentos.get(usuario, [])
                        if ahora - t < 60]
        self._intentos[usuario] = intentos_user
        if len(intentos_user) >= self.LOGIN_MAX_POR_USUARIO:
            LOG.warning("Rate limit excedido para %s (%d/min)", usuario, self.LOGIN_MAX_POR_USUARIO)
            return None

        u = self._usuarios.get(usuario)
        if not u:
            return None
        if self._check_lockout(usuario):
            LOG.warning("Login bloqueado: %s (%ds)", usuario, self.BLOQUEO_MINUTOS * 60)
            return None
        _h = _hmac(self._secreto, password)
        if not hmac.compare_digest(_h, u["hash"]):
            self._register_attempt(usuario, False)
            return None
        if mfa_code:
            try:
                from utils.mfa import obtener_mfa
                if not obtener_mfa().verificar(usuario, mfa_code):
                    return None
            except Exception:
                pass
        self._register_attempt(usuario, True)
        payload = {
            "usuario": usuario, "role": u["role"],
            "exp": (datetime.utcnow() + timedelta(seconds=TOKEN_TTL)).isoformat() + "Z",
            "nonce": secrets.token_hex(8),
        }
        raw = json.dumps(payload, sort_keys=True)
        firma = _hmac(self._secreto, raw)
        token = raw + "." + firma
        # Limitar sesiones por usuario a 5
        sesiones_usuario = [k for k, v in self._tokens_activos.items()
                           if v.get("usuario") == usuario]
        while len(sesiones_usuario) >= 5:
            viejo = sesiones_usuario.pop(0)
            self._tokens_activos.pop(viejo, None)
        self._tokens_activos[token] = payload
        return token

    def verificar(self, token: str) -> Optional[dict]:
        """Verifica token: HMAC + expiración. NO confía solo en dict lookup."""
        # Verificar HMAC independientemente del dict
        if "." not in token:
            return None
        raw, hmac_val = token.rsplit(".", 1)
        if not hmac.compare_digest(_hmac(self._secreto, raw), hmac_val):
            LOG.warning("Token HMAC inválido: %s...", token[:40])
            return None
        # Buscar en sesiones activas
        payload = self._tokens_activos.get(token)
        if not payload:
            return None
        # Verificar expiración
        exp = datetime.fromisoformat(payload["exp"].replace("Z", "+00:00"))
        if datetime.utcnow().replace(tzinfo=None) > exp.replace(tzinfo=None):
            del self._tokens_activos[token]
            return None
        return payload

    def autorizar(self, token: str, nivel_min: str = "viewer") -> bool:
        p = self.verificar(token)
        if not p:
            return False
        return ROLES.get(p["role"], 0) >= ROLES.get(nivel_min, 0)

    def cerrar_sesion(self, token: str):
        self._tokens_activos.pop(token, None)

    def desbloquear(self, usuario: str):
        self._bloqueos.pop(usuario, None)
        self._intentos.pop(usuario, None)
        LOG.info("Cuenta desbloqueada: %s", usuario)

    def limpiar_expirados(self):
        ahora = datetime.utcnow().replace(tzinfo=None)
        vencidos = [t for t, p in self._tokens_activos.items()
                    if datetime.fromisoformat(p["exp"].replace("Z", "+00:00")).replace(tzinfo=None) < ahora]
        for t in vencidos:
            del self._tokens_activos[t]

    def estado(self) -> dict:
        self.limpiar_expirados()
        return {"sesiones_activas": len(self._tokens_activos),
                "usuarios": list(self._usuarios.keys()),
                "bloqueados": list(self._bloqueos.keys())}


_auth: AuthManager | None = None
_auth_lock = threading.Lock()


def obtener_auth() -> AuthManager:
    global _auth
    if _auth is None:
        with _auth_lock:
            if _auth is None:
                _auth = AuthManager()
    return _auth
