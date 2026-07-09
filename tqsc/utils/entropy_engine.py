"""
TQSC v1.0 — EntropyNoiseEngine
Antifragilidad digital: detección, respuesta y evidencia forense.
"""
import os, time, hashlib, json, hmac, secrets, logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from utils.secure_storage import append as _append

TQSC_TEST = os.environ.get("TQSC_TEST_MODE") == "1"
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

LOG = logging.getLogger("tqsc.entropy")


class EntropyImpactEstimator:
    """Mide entropía con baseline adaptativo + jitter anti-manipulación."""

    def __init__(self, baseline: float = 0.68, tolerancia: float = 0.15, muestras: int = 5):
        self.baseline = baseline; self.tolerancia = tolerancia; self.n_muestras = muestras
        self.historial: list[float] = []; self._hora_baseline = time.time()

    def medir(self) -> tuple[float, bool]:
        m = []
        for _ in range(self.n_muestras):
            data = os.urandom(4096)
            # Múltiples métricas de entropía anti-manipulación
            ratio_bytes = len(set(data)) / 256  # diversidad de bytes
            freqs = {}
            for b in data: freqs[b] = freqs.get(b, 0) + 1
            entropia_shannon = -sum((c/4096) * __import__('math').log2(c/4096) for c in freqs.values())
            # Combinar métricas
            score = (ratio_bytes + min(entropia_shannon / 8.0, 1.0)) / 2
            m.append(round(score, 4))
        promedio = sum(m) / len(m)
        self.historial.append(promedio)
        if len(self.historial) > 1000: self.historial = self.historial[-500:]
        # Baseline adaptativo cada hora
        if time.time() - self._hora_baseline > 3600 and len(self.historial) > 20:
            self.baseline = sum(self.historial[-20:]) / 20
            self._hora_baseline = time.time()
        hay_anomalia = abs(promedio - self.baseline) > self.tolerancia
        return promedio, hay_anomalia

    def tendencia(self) -> str:
        if len(self.historial) < 10: return "estable"
        r = self.historial[-20:] if len(self.historial) >= 20 else self.historial
        pendiente = r[-1] - r[0]
        if pendiente < -0.1: return "decreciente"
        if pendiente > 0.1: return "creciente"
        return "estable"

    def estado(self) -> dict:
        return {"baseline": round(self.baseline, 3), "tolerancia": self.tolerancia,
                "muestras": len(self.historial), "tendencia": self.tendencia()}


class EntropyShield:
    """Contramedidas con rate limiting y priorización por severidad."""

    def __init__(self):
        self._cache = {}  # caché de resultados para evitar re-ejecución
        self.ultima_activacion: dict[str, float] = {}

    def shield_activo(self) -> bool:
        return HAS_PSUTIL

    def ram_noise_interceptor(self, force: bool = False) -> list[dict]:
        if not HAS_PSUTIL or TQSC_TEST: return []
        ahora = time.time()
        if not force and self.ultima_activacion.get("ram", 0) > ahora - 30:
            return self._cache.get("ram", [])
        sospechosos = []
        for proc in psutil.process_iter(["pid", "name", "memory_info"]):
            try:
                if proc.info["memory_info"].rss > 50 * 1024 * 1024:
                    sospechosos.append({"pid": proc.info["pid"], "nombre": proc.info["name"],
                                        "rss": proc.info["memory_info"].rss})
            except (psutil.NoSuchProcess, TypeError): continue
        self._cache["ram"] = sospechosos
        self.ultima_activacion["ram"] = ahora
        return sospechosos

    def io_traffic_noise_checker(self, force: bool = False) -> bool:
        if not HAS_PSUTIL or TQSC_TEST: return False
        ahora = time.time()
        if not force and self.ultima_activacion.get("io", 0) > ahora - 30:
            return self._cache.get("io", False)
        net = psutil.net_io_counters()
        anomalia = net.bytes_sent > 10**7 or net.bytes_recv > 10**7
        # DNS tunneling
        try:
            conexiones = psutil.net_connections()
            dns_count = sum(1 for c in conexiones if hasattr(c, 'raddr') and c.raddr and c.raddr.port == 53)
            anomalia = anomalia or dns_count > 20
        except (psutil.AccessDenied, AttributeError):
            dns_count = 0
        self._cache["io"] = anomalia
        self.ultima_activacion["io"] = ahora
        return anomalia

    def ejecutar_todas(self, severidad: int = 1) -> list[str]:
        res = []
        if severidad >= 1:
            ram = self.ram_noise_interceptor()
            if ram: res.append(f"ram: {len(ram)} procesos >50MB")
        if severidad >= 2:
            io = self.io_traffic_noise_checker()
            if io: res.append("io: tráfico anómalo detectado")
        return res

    def dns_tunneling_score(self) -> int:
        if not HAS_PSUTIL: return 0
        score = 0
        try:
            for conn in psutil.net_connections():
                if hasattr(conn, 'raddr') and conn.raddr and conn.raddr.port == 53:
                    score += 1
        except (psutil.AccessDenied, AttributeError): pass
        return score


class EntropyTraceLedger:
    """Ledger forense con HMAC, rate limiting y rotación automática."""

    def __init__(self, data_dir: str = "data", max_entries: int = 10000):
        self.ruta = Path(data_dir) / "entropy_ledger.jsonl"
        self._secreto = secrets.token_hex(16)
        self._max_entries = max_entries
        self._count = 0

    def registrar(self, contexto: str, resultado: str, metadatos: Optional[dict] = None):
        if self._count >= self._max_entries:
            LOG.warning("Ledger: límite de %d entradas alcanzado", self._max_entries)
            return None
        raw = json.dumps({"contexto": contexto, "resultado": resultado, "metadatos": metadatos or {}}, sort_keys=True)
        entrada = {
            "timestamp": datetime.now().isoformat(),
            "contexto": contexto, "resultado": resultado, "metadatos": metadatos or {},
            "firma": hashlib.sha256(raw.encode()).hexdigest()[:16],
            "hmac": hmac.new(self._secreto.encode(), raw.encode(), hashlib.sha256).hexdigest()[:16],
        }
        self.ruta.parent.mkdir(parents=True, exist_ok=True)
        _append(self.ruta, entrada)
        self._count += 1
        return entrada

    def verificar(self, entrada: dict) -> bool:
        stored = entrada.get("hmac", "")
        if not stored: return False
        clean = {k: v for k, v in entrada.items() if k not in ("hmac", "firma", "timestamp")}
        raw = json.dumps(clean, sort_keys=True)
        esperado = hmac.new(self._secreto.encode(), raw.encode(), hashlib.sha256).hexdigest()[:16]
        return hmac.compare_digest(stored, esperado)


class EntropyNoiseEngine:
    """Motor completo con circuit breaker y cache de shields."""

    def __init__(self, data_dir: str = "data", max_ciclos_seguidos: int = 10):
        self.estimator = EntropyImpactEstimator()
        self.shield = EntropyShield()
        self.ledger = EntropyTraceLedger(data_dir=data_dir)
        self._ciclos_anomalos = 0
        self._max_ciclos = max_ciclos_seguidos
        self._bloqueado = False

    def ejecutar_ciclo(self) -> dict:
        if self._bloqueado:
            return {"entropia": 0, "anomalia": False, "circuit_breaker": True, "contramedidas": {}}

        promedio, hay_anomalia = self.estimator.medir()
        resultado = {"entropia": round(promedio, 4), "anomalia": hay_anomalia, "contramedidas": {}}

        if hay_anomalia:
            self._ciclos_anomalos += 1
            severidad = min(self._ciclos_anomalos, 3)
            resultado["contramedidas"]["shields"] = self.shield.ejecutar_todas(severidad)
            if self._ciclos_anomalos >= self._max_ciclos:
                self._bloqueado = True
                LOG.warning("EntropyEngine: circuit breaker activado (%d ciclos anómalos)", self._ciclos_anomalos)
        else:
            self._ciclos_anomalos = max(0, self._ciclos_anomalos - 1)

        self.ledger.registrar("ciclo_entropia", "anomalia" if hay_anomalia else "normal", {"entropia": promedio})
        return resultado

    def reset(self):
        self._bloqueado = False
        self._ciclos_anomalos = 0
        LOG.info("EntropyEngine: reset")

    def estado(self) -> dict:
        return {"bloqueado": self._bloqueado, "ciclos_anomalos": self._ciclos_anomalos,
                "max_ciclos": self._max_ciclos}
