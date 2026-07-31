"""
tqsc/utils/audit.py — Auditoría inmutable PCI DSS §10.
Append thread-safe con lock contra race conditions.
Cadena HMAC: cada entrada enlaza a la anterior.
"""
import json, logging, os, hmac, hashlib, time, threading
from pathlib import Path
from datetime import datetime

LOG = logging.getLogger("tqsc.audit")


class AuditTrail:
    def __init__(self, ruta: str, secreto: str = "", siem: bool = True):
        self.ruta = Path(ruta)
        self.ruta.parent.mkdir(parents=True, exist_ok=True)
        self._secreto = secreto or os.environ.get("TQSC_AUDIT_SECRET", "")
        if not self._secreto:
            import secrets; self._secreto = secrets.token_hex(16)
        self._cadena: list[dict] = []
        self._siem = siem
        self._lock = threading.Lock()
        self._cargar()

    def _append(self, entrada: dict):
        with self._lock:
            with open(self.ruta, "a") as f:
                f.write(json.dumps(entrada, ensure_ascii=False) + "\n")
                f.flush()

    def _ruta_idx(self) -> Path:
        return self.ruta.with_suffix(".idx")

    def _cargar(self):
        if self._ruta_idx().exists():
            try:
                self._cadena = json.loads(self._ruta_idx().read_text())
            except (json.JSONDecodeError, OSError):
                self._cadena = []

    def _persistir_idx(self):
        self._ruta_idx().write_text(json.dumps(self._cadena[-1000:], default=str))

    def _hash_entrada(self, entrada: dict) -> str:
        raw = json.dumps(entrada, sort_keys=True).encode()
        return hashlib.sha256(raw).hexdigest()

    def _env_siem(self, entrada: dict):
        if not self._siem: return
        try:
            from utils.siem import obtener_alertas
            obtener_alertas().alertar(
                entrada.get("severidad", "INFO"),
                f"audit/{entrada.get('accion','?')}",
                f"{entrada.get('usuario','?')} | {entrada.get('recurso','?')} | {entrada.get('detalle','?')}")
        except Exception:
            pass

    def registrar(self, accion: str, usuario: str, recurso: str,
                  detalle: str = "", severidad: str = "INFO") -> str:
        prev_hash = self._cadena[-1]["hash"] if self._cadena else "0" * 64
        entrada = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "accion": accion, "usuario": usuario,
            "recurso": recurso, "detalle": detalle,
            "severidad": severidad, "prev_hash": prev_hash,
            "nonce": os.urandom(4).hex(),
        }
        entrada["hash"] = self._hash_entrada(entrada)
        raw = json.dumps(entrada, sort_keys=True).encode()
        entrada["hmac"] = hmac.new(self._secreto.encode(), raw, hashlib.sha256).hexdigest()
        self._append(entrada)
        idx_entry = {"ts": entrada["timestamp"], "hash": entrada["hash"],
                     "prev": prev_hash, "accion": accion, "usuario": usuario}
        self._cadena.append(idx_entry)
        self._persistir_idx()
        LOG.info("Audit: %s | %s | %s", accion, usuario, recurso)
        self._env_siem(entrada)
        return entrada["hash"]

    def verificar(self, desde: int = 0) -> list[dict]:
        entradas = []; prev = "0" * 64
        with self._lock:
            with open(self.ruta) as f:
                for i, line in enumerate(f):
                    if i < desde: continue
                    try: e = json.loads(line)
                    except json.JSONDecodeError:
                        return [{"linea": i, "error": "json_invalido"}]
                    hash_actual = e.pop("hash", ""); hmac_actual = e.pop("hmac", "")
                    esperado = self._hash_entrada(e)
                    e["hash"] = hash_actual
                    raw = json.dumps(e, sort_keys=True).encode()
                    hmac_ok = hmac.compare_digest(hmac_actual,
                        hmac.new(self._secreto.encode(), raw, hashlib.sha256).hexdigest()) if hmac_actual else False
                    e["hmac"] = hmac_actual
                    e["integro"] = (esperado == hash_actual) and hmac_ok and (prev == e.get("prev_hash", ""))
                    if not e["integro"]:
                        if esperado != hash_actual: e["error"] = "hash_invalido"
                        elif not hmac_ok: e["error"] = "hmac_invalido"
                        else: e["error"] = "cadena_rota"
                    entradas.append(e); prev = hash_actual
        return entradas

    def exportar(self) -> list[dict]:
        entradas = []
        with self._lock:
            with open(self.ruta) as f:
                for line in f:
                    try: entradas.append(json.loads(line))
                    except json.JSONDecodeError:
                        entradas.append({"error": "json_invalido", "raw": line[:200]})
        return entradas

    def estado(self) -> dict:
        return {"entradas": len(self._cadena), "archivo": str(self.ruta),
                "ultimo_hash": self._cadena[-1]["hash"] if self._cadena else "0" * 64}


_audit: AuditTrail | None = None
_audit_lock = threading.Lock()


def obtener_audit() -> AuditTrail:
    global _audit
    if _audit is None:
        with _audit_lock:
            if _audit is None:
                data_dir = os.environ.get("TQSC_HOME", "data")
                _audit = AuditTrail(os.path.join(data_dir, "audit.jsonl"))
    return _audit
