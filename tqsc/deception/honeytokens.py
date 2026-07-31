"""
tqsc/deception/honeytokens.py — Honeytokens con formatos reales + plantado en disco.
"""
import logging, secrets, json, hmac, hashlib, base64, time, uuid, threading
from pathlib import Path
from typing import Optional
from .interfaces import ITokenGenerator
from .models import Token
from .storage import SQLiteStorage
from .alert_engine import AlertEngine

LOG = logging.getLogger("tqsc.deception.honeytokens")


class HoneytokenEngine(ITokenGenerator):
    """Genera honeytokens con formatos criptográficos reales y los planta en disco."""

    def __init__(self, storage: SQLiteStorage, alerts: AlertEngine, tqsc_home: str = "data"):
        self._storage = storage
        self._alerts = alerts
        self._tqsc_home = tqsc_home
        self._lock = threading.Lock()

    @staticmethod
    def _aws() -> str:
        return json.dumps({"aws_access_key_id": "AKIA" + secrets.token_hex(8).upper(),
                           "aws_secret_access_key": base64.b64encode(secrets.token_bytes(30)).decode()})

    @staticmethod
    def _jwt() -> str:
        h = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(json.dumps({"sub": "svc", "role": "admin", "iat": int(time.time())}).encode()).rstrip(b"=").decode()
        s = base64.urlsafe_b64encode(hmac.new(secrets.token_hex(16).encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
        return f"{h}.{p}.{s}"

    def generar(self, tipo: str, ubicacion: str, memo: str = "") -> dict:
        generadores = {
            "aws_key": self._aws, "jwt": self._jwt,
            "db_string": lambda: f"postgresql://{secrets.token_hex(4)}_admin:{secrets.token_urlsafe(16)}@db-{secrets.token_hex(4)}.internal:5432/prod",
            "slack_token": lambda: f"xoxb-{secrets.randbits(32)}-{secrets.randbits(48)}-{secrets.token_hex(16)}",
            "github_token": lambda: f"github_pat_{secrets.token_hex(22)}_{secrets.token_hex(38)}",
        }
        valor = generadores.get(tipo, lambda: f"sk-{secrets.token_hex(32)}")()
        t = Token(tipo=tipo, valor=valor, ubicacion=ubicacion, memo=memo, creado=time.time())
        with self._lock:
            self._storage.guardar_token(t)
        self._plantar(t)
        LOG.info("🔹 Honeytoken %s (%s) generado", t.id[:8], tipo)
        return t.to_dict()

    def _plantar(self, t: Token):
        nombres = {"aws_key": ".aws/credentials", "jwt": ".config/token.jwt",
                   "db_string": ".env", "slack_token": ".config/slack.env",
                   "github_token": ".config/github.env"}
        nombre = nombres.get(t.tipo, f".config/{t.tipo}.txt")
        try:
            ruta = Path(self._tqsc_home) / nombre
            ruta.parent.mkdir(parents=True, exist_ok=True)
            if t.tipo == "aws_key":
                d = json.loads(t.valor)
                ruta.write_text(f"[default]\naws_access_key_id={d['aws_access_key_id']}\naws_secret_access_key={d['aws_secret_access_key']}\n")
            else:
                ruta.write_text(t.valor + "\n")
            LOG.info("📝 Plantado: %s", ruta)
        except (OSError, PermissionError):
            pass

    def verificar(self, valor: str) -> Optional[dict]:
        token_dict = self._storage.obtener_token_por_valor(valor)
        if token_dict:
            self._storage.actualizar_estado(token_dict["id"], "disparado")
            alerta = {"tipo": "honeytoken", "componente": "honeytokens",
                      "detalle": f"Token {token_dict['tipo']} usado desde {token_dict['ubicacion']}",
                      "severidad": "critica"}
            self._alerts.disparar(alerta)
            LOG.critical("🚨 HONEYTOKEN DISPARADO: %s", token_dict['tipo'])
            return alerta
        return None

    def iniciar(self):
        pass

    def detener(self):
        pass
