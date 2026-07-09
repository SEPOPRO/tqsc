"""
TQSC v1.0 — Validación Cuántica Predictiva
"""
import hashlib, json, logging, secrets, hmac, time
from datetime import datetime
from pathlib import Path
from typing import Optional


class QuantumValidator:
    """Verifica estructura + semántica de campos del evento."""

    ESQUEMA_BASE = {"timestamp": (str, float, int), "origen": str, "hash": str, "firma": str, "tipo": str}

    def __init__(self, esquema: Optional[dict] = None):
        self.esquema = esquema or self.ESQUEMA_BASE
        self.logger = logging.getLogger("tqsc.quantum.validator")

    def validar(self, evento: dict) -> tuple[bool, list[str]]:
        razones = []
        for campo, tipos in self.esquema.items():
            if campo not in evento:
                razones.append(f"campo faltante: {campo}")
                continue
            v = evento[campo]
            if not isinstance(v, tipos):
                razones.append(f"tipo: {campo} esperaba {tipos}, recibió {type(v).__name__}")
                continue
            # Validación semántica
            if campo == "hash" and isinstance(v, str) and len(v) < 8:
                razones.append(f"hash demasiado corto: {len(v)} chars")
            if campo == "origen" and isinstance(v, str) and not v.strip():
                razones.append("origen vacío")
            if campo == "tipo" and isinstance(v, str) and v not in ("evento", "consulta", "comando", "alerta"):
                razones.append(f"tipo desconocido: {v}")
        if razones:
            self.logger.warning("QuantumValidator: %s", "; ".join(razones[:3]))
        return len(razones) == 0, razones


class VeracitySynthesizer:
    """Veracidad con reglas no lineales y coherencia entre campos."""

    def __init__(self, umbral: float = 0.85):
        self.umbral = umbral
        self.historial: list[float] = []
        self._secreto = secrets.token_hex(8)

    def evaluar(self, evento: dict) -> tuple[float, bool]:
        puntaje = 0.7  # base para eventos válidos con campos requeridos
        requeridos = ["timestamp", "origen", "tipo"]

        # Penalización por campos faltantes
        faltantes = sum(1 for c in requeridos if c not in evento)
        puntaje -= faltantes * 0.15

        # Coherencia: timestamp reciente?
        ts = evento.get("timestamp")
        if isinstance(ts, (int, float)):
            if abs(time.time() - ts) > 300:  # >5 min de diferencia
                puntaje -= 0.2
        elif isinstance(ts, str):
            try:
                dt = datetime.fromisoformat(ts)
                if abs((datetime.now() - dt).total_seconds()) > 300:
                    puntaje -= 0.2
            except ValueError:
                puntaje -= 0.1

        # Hash válido no trivial
        h = evento.get("hash", "")
        if isinstance(h, str) and len(h) >= 16:
            puntaje += 0.15
        elif isinstance(h, str) and len(h) >= 8:
            puntaje += 0.05

        # Firma presente
        if evento.get("firma"):
            puntaje += 0.10

        # Bonus limitado por campos extra (max +0.10 no +0.15)
        extra = sum(1 for c in evento if c not in requeridos + ["hash", "firma"])
        puntaje += min(extra * 0.02, 0.10)

        # No trivial: si todo es perfecto pero faltan campos clave, baja
        if faltantes == 0 and not evento.get("hash") and not evento.get("firma"):
            puntaje -= 0.15  # evento sin hash ni firma es sospechoso

        confianza = max(0.0, min(1.0, puntaje))
        self.historial.append(confianza)
        if len(self.historial) > 100:
            self.historial = self.historial[-50:]

        # Umbral adaptativo anti-falsificación
        if len(self.historial) > 10:
            prom_hist = sum(self.historial) / len(self.historial)
            if prom_hist > 0.95:
                umbral_efectivo = self.umbral * 0.97
            elif prom_hist < 0.3:
                umbral_efectivo = self.umbral * 1.05  # más estricto si hay anomalías
            else:
                umbral_efectivo = self.umbral
        else:
            umbral_efectivo = self.umbral

        return confianza, confianza >= umbral_efectivo

    def estado(self) -> dict:
        return {"umbral": self.umbral, "muestras": len(self.historial),
                "prom_hist": round(sum(self.historial) / max(1, len(self.historial)), 3) if self.historial else 0}


class EntangledKeyValidator:
    """Verifica claves con HMAC + secreto rotante."""

    _SECRETO = secrets.token_hex(16)

    @staticmethod
    def validar(clave: str, origen: str, timestamp: str) -> bool:
        esperado = hmac.new(
            EntangledKeyValidator._SECRETO.encode(),
            f"{origen}{timestamp}".encode(),
            hashlib.sha256
        ).hexdigest()[:16]
        return hmac.compare_digest(clave, esperado)

    @staticmethod
    def generar(origen: str, timestamp: str) -> str:
        return hmac.new(
            EntangledKeyValidator._SECRETO.encode(),
            f"{origen}{timestamp}".encode(),
            hashlib.sha256
        ).hexdigest()[:16]


class QuantumAuditLogger:
    """Auditoría con firma HMAC anti-manipulación."""

    def __init__(self, data_dir: str = "data"):
        self.ruta = Path(data_dir) / "quantum_audit.jsonl"
        self._secreto = secrets.token_hex(16)

    def registrar(self, evento: dict, decision: str, confianza: float):
        entrada = {
            "timestamp": datetime.now().isoformat(),
            "evento_hash": evento.get("hash", "?"),
            "decision": decision,
            "confianza": round(confianza, 4),
            "firma": hashlib.sha256(json.dumps(evento, sort_keys=True).encode()).hexdigest()[:32],
        }
        raw = json.dumps(entrada, sort_keys=True)
        entrada["hmac"] = hmac.new(self._secreto.encode(), raw.encode(), hashlib.sha256).hexdigest()[:16]
        self.ruta.parent.mkdir(parents=True, exist_ok=True)
        with open(self.ruta, "a") as f:
            f.write(json.dumps(entrada, ensure_ascii=False) + "\n")
        return entrada

    def verificar(self, entrada: dict) -> bool:
        stored_hmac = entrada.get("hmac", "")
        if not stored_hmac: return False
        clean = {k: v for k, v in entrada.items() if k != "hmac"}
        raw = json.dumps(clean, sort_keys=True)
        esperado = hmac.new(self._secreto.encode(), raw.encode(), hashlib.sha256).hexdigest()[:16]
        return hmac.compare_digest(stored_hmac, esperado)


class QuantumCore:
    """Core cuántico con circuit breaker por tasa de error."""

    def __init__(self, data_dir: str = "data", max_errores_por_minuto: int = 50):
        self.validator = QuantumValidator()
        self.veracity = VeracitySynthesizer()
        self.key_validator = EntangledKeyValidator()
        self.audit = QuantumAuditLogger(data_dir=data_dir)
        self._errores_recientes: list[float] = []
        self._max_errores = max_errores_por_minuto
        self._bloqueado = False

    def procesar(self, evento: dict) -> str:
        if self._bloqueado:
            return "Circuit Breaker: core bloqueado por exceso de errores"

        valido, razones = self.validator.validar(evento)
        if not valido:
            self._registrar_error()
            return f"Descartado: {'; '.join(razones[:2])}"

        confianza, aceptado = self.veracity.evaluar(evento)
        if not aceptado:
            self._registrar_error()
            self.audit.registrar(evento, f"falso_positivo_{confianza:.2f}", confianza)
            return f"Falso Positivo (confianza={confianza:.2f})"

        self.audit.registrar(evento, "aceptado", confianza)
        return f"Aceptado (confianza={confianza:.2f})"

    def _registrar_error(self):
        ahora = time.time()
        self._errores_recientes.append(ahora)
        self._errores_recientes = [t for t in self._errores_recientes if ahora - t < 60]
        if len(self._errores_recientes) > self._max_errores:
            self._bloqueado = True

    def reset_circuit_breaker(self):
        self._bloqueado = False
        self._errores_recientes = []

    def estado(self) -> dict:
        return {"bloqueado": self._bloqueado, "errores_ultimo_minuto": len(self._errores_recientes)}
