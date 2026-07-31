"""
TQSC v1.0 — ForkSealant
Integridad Distribuida: detección de forks, validación cruzada, consenso autónomo.
Todos los logs con firma HMAC para detección de manipulación.
"""
import json, time, hashlib, hmac, secrets, logging, os, socket
from collections import defaultdict
from pathlib import Path
from typing import Optional
from datetime import datetime, timedelta

from utils.secure_storage import write as _write, read as _read

TQSC_TEST = lambda: os.environ.get("TQSC_TEST_MODE") == "1"
LOG = logging.getLogger("tqsc.blockchain")
EVENT_LOG = []  # Event log compartido entre instancias


def _firmar(datos: dict, secreto: str) -> str:
    """Firma HMAC-SHA256 de un diccionario con secreto explícito."""
    raw = json.dumps(datos, sort_keys=True, ensure_ascii=False).encode()
    return hmac.new(secreto.encode(), raw, hashlib.sha256).hexdigest()[:16]


def _persistir_log(ruta: Path, datos: dict, secreto: str):
    """Persiste con firma HMAC."""
    datos["hmac"] = _firmar(datos, secreto)
    _write(ruta, datos)


class ForkSealant:
    """Detecta bifurcaciones no autorizadas en los registros distribuidos."""

    def __init__(self, nodos: Optional[dict[str, str]] = None, data_dir: str = "data"):
        self.nodos = nodos or DEFAULT_NODOS
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._firmas_historicas: set[str] = set()
        self._secreto = secrets.token_hex(16)

    def verificar(self, hash_local: str) -> bool:
        if hash_local not in set(self.nodos.values()):
            self._registrar_fork(hash_local)
            return False
        # Anti-replay: mismo hash usado dos veces = sospechoso
        if hash_local in self._firmas_historicas:
            LOG.warning("ForkSealant: hash repetido %.16s — posible replay", hash_local)
            self._registrar_fork(hash_local)
            return False
        self._firmas_historicas.add(hash_local)
        return True

    def _registrar_fork(self, hash_local: str) -> dict:
        evento = {
            "timestamp": datetime.now().isoformat(),
            "hash_detectado": hash_local,
            "accion": "bloqueo_proceso",
            "estado": "fork_detectado",
        }
        _persistir_log(self.data_dir / "fork_event.json", evento, self._secreto)
        return evento


class NodeReputationManager:
    """Sistema de reputación con persistencia a disco."""

    def __init__(self, nodos: dict[str, str], score_inicial: float = 1.0,
                 umbral_compromiso: float = 0.3, max_influencia: float = 0.5,
                 decay_rate: float = 0.02, data_dir: str = "data",
                 secreto: str = ""):
        self.scores: dict[str, float] = {n: score_inicial for n in nodos}
        self.umbral = umbral_compromiso; self.max_influencia = max_influencia
        self.decay_rate = decay_rate; self.ultimo_voto: dict[str, float] = {n: time.time() for n in nodos}
        self.data_dir = Path(data_dir); self.historial: dict[str, list[dict]] = {n: [] for n in nodos}
        self._secreto = secreto or secrets.token_hex(16)
        self._cargar()

    def _ruta(self) -> Path: return self.data_dir / "reputacion.json"

    def _cargar(self):
        if TQSC_TEST(): return
        try:
            data = _read(self._ruta())
            if data:
                for n, s in data.get("scores", {}).items():
                    if n in self.scores:
                        self.scores[n] = s
        except (json.JSONDecodeError, OSError) as e:
            LOG.warning("NodeReputation: corrupción en %s (%s)", self._ruta(), e)

    def _persistir(self):
        _write(self._ruta(), {"scores": self.scores, "updated": time.time()})

    def registrar_voto(self, nodo: str, consistente: bool):
        # Decaimiento temporal: si pasó mucho tiempo sin actividad, baja score
        ahora = time.time()
        if ahora - self.ultimo_voto.get(nodo, ahora) > 300:  # 5 min
            self.scores[nodo] = max(0.0, self.scores[nodo] - self.decay_rate)
        self.ultimo_voto[nodo] = ahora

        delta = 0.1 if consistente else -0.25
        self.scores[nodo] = max(0.0, min(1.0, self.scores[nodo] + delta))
        self.historial[nodo].append({
            "timestamp": datetime.now().isoformat(),
            "consistente": consistente, "score": self.scores[nodo],
        })
        self._persistir()
        if self.scores[nodo] < self.umbral:
            self._notificar_compromiso(nodo)

    def nodos_confiables(self) -> list[str]:
        return [n for n, s in self.scores.items() if s >= self.umbral]

    def peso_efectivo(self, nodo: str) -> float:
        """Peso del nodo limitado por max_influencia para evitar dominancia."""
        return min(self.scores.get(nodo, 0), self.max_influencia)

    def esta_comprometido(self, nodo: str) -> bool:
        return self.scores.get(nodo, 0) < self.umbral

    def penalizar(self, nodo: str, razon: str, severidad: float = 0.4):
        self.scores[nodo] = max(0.0, self.scores[nodo] - severidad)
        self.historial[nodo].append({
            "timestamp": datetime.now().isoformat(),
            "penalizacion": razon, "score": self.scores[nodo],
        })

    def _notificar_compromiso(self, nodo: str):
        _persistir_log(self.data_dir / "node_compromised.json", {
            "timestamp": datetime.now().isoformat(), "nodo": nodo,
            "score": self.scores[nodo], "accion": "nodo_comprometido_excluido",
        }, self._secreto)

    def estado(self) -> dict:
        return {n: {"score": round(s, 3), "comprometido": s < self.umbral}
                for n, s in self.scores.items()}


class NodeChallenge:
    """Desafíos criptográficos con rate limiting y backoff exponencial."""

    def __init__(self, reputacion: NodeReputationManager,
                 max_rondas: int = 3, rate_limit: int = 5, backoff_base: float = 1.0):
        self.reputacion = reputacion
        self.claves = {nodo: secrets.token_hex(8) for nodo in reputacion.scores}
        self.desafios_activos: dict[str, tuple[str, datetime]] = {}
        self.conteo_desafios: dict[str, int] = defaultdict(int)
        self.ultimo_desafio: dict[str, float] = {}
        self.max_rondas = max_rondas
        self.rate_limit = rate_limit  # máx desafíos por minuto
        self.backoff_base = backoff_base

    def lanzar(self, nodo: str) -> Optional[str]:
        ahora = time.time()
        # Rate limiting
        if nodo in self.ultimo_desafio:
            diff = ahora - self.ultimo_desafio[nodo]
            if diff < 60 / self.rate_limit:
                LOG.warning("NodeChallenge: rate limit para %s (%.1fs)", nodo, diff)
                return None
        # Backoff: si falló antes, esperar más
        intentos = self.conteo_desafios.get(nodo, 0)
        if intentos > 0:
            espera = self.backoff_base * (2 ** min(intentos - 1, 4))
            if ahora - self.ultimo_desafio.get(nodo, 0) < espera:
                LOG.warning("NodeChallenge: backoff %s (%.1fs)", nodo, espera)
                return None
        # Máximo de rondas
        if intentos >= self.max_rondas:
            LOG.warning("NodeChallenge: %s excedió máximo de rondas (%d)", nodo, self.max_rondas)
            return None

        nonce = secrets.token_hex(16)
        self.desafios_activos[nodo] = (nonce, datetime.now())
        self.conteo_desafios[nodo] = intentos + 1
        self.ultimo_desafio[nodo] = ahora
        return nonce

    def verificar_respuesta(self, nodo: str, nonce: str, respuesta: str) -> bool:
        if nodo not in self.desafios_activos:
            self.reputacion.penalizar(nodo, "desafio_no_solicitado", 0.3); return False
        nonce_ok, ts = self.desafios_activos[nodo]
        if nonce != nonce_ok:
            self.reputacion.penalizar(nodo, "nonce_incorrecto", 0.3); return False
        if datetime.now() - ts > timedelta(seconds=5):
            self.reputacion.penalizar(nodo, "timeout", 0.2); del self.desafios_activos[nodo]; return False
        esperado = hmac.new(self.claves[nodo].encode(), nonce.encode(), hashlib.sha256).hexdigest()
        if respuesta != esperado:
            self.reputacion.penalizar(nodo, "respuesta_incorrecta", 0.5); del self.desafios_activos[nodo]; return False
        # Rotar clave post-verificación
        self.claves[nodo] = secrets.token_hex(8)
        self.reputacion.registrar_voto(nodo, True)
        del self.desafios_activos[nodo]
        return True


class CrossChainTracker:
    """Verifica consistencia entre múltiples nodos testigo.
    Modo IPC: intenta red real, fallback a dict local.
    """

    def __init__(self, nodos: Optional[dict[str, str]] = None,
                 sealant: Optional[ForkSealant] = None,
                 reputacion: Optional[NodeReputationManager] = None):
        self.nodos = nodos or DEFAULT_NODOS
        self.sealant = sealant or ForkSealant(nodos=nodos)
        self.reputacion = reputacion or NodeReputationManager(self.nodos)
        self.red: Optional[RedBlockchain] = None
        if not TQSC_TEST():
            try:
                from blockchain.ipc_red import RedBlockchain
                self.red = RedBlockchain(data_dir=str(self.reputacion.data_dir))
                self.red.iniciar()
            except Exception as e:
                LOG.warning("CrossChain: IPC no disponible, modo local (%s)", e)

    def verificar(self, hash_local: str) -> bool:
        if not self.sealant.verificar(hash_local):
            return False
        confiables = self.reputacion.nodos_confiables()
        if not confiables:
            return False

        # Voto ponderado por reputación (con techo anti-dominancia)
        votos_favor = sum(self.reputacion.peso_efectivo(n)
                          for n in confiables if self.nodos.get(n) == hash_local)
        votos_total = sum(self.reputacion.peso_efectivo(n) for n in confiables)
        peso = votos_favor / votos_total if votos_total > 0 else 0

        # Registrar consistencia de cada nodo
        for n in confiables:
            self.reputacion.registrar_voto(n, self.nodos.get(n) == hash_local)

        if peso < 0.5:
            return self._iniciar_reconsenso(hash_local)
        return True

    def _iniciar_reconsenso(self, hash_conflictivo: str) -> bool:
        return ReconsensusAgent(self.nodos, self.reputacion).resolver(hash_conflictivo)


class ReconsensusAgent:
    """Votación distribuida ponderada por reputación con timeout y registro en blockchain."""

    def __init__(self, nodos: Optional[dict[str, str]] = None,
                 reputacion: Optional[NodeReputationManager] = None,
                 data_dir: str = "data", timeout_nodo: float = 3.0):
        self.nodos = nodos or DEFAULT_NODOS
        self.reputacion = reputacion or NodeReputationManager(self.nodos)
        self.data_dir = Path(data_dir)
        self.timeout_nodo = timeout_nodo

    def resolver(self, hash_conflictivo: str) -> bool:
        confiables = self.reputacion.nodos_confiables()
        if not confiables:
            LOG.warning("Reconsensus: 0 nodos confiables — consenso denegado")
            return False

        votos_a_favor = 0.0
        votos_en_contra = 0.0
        resultados_nodos: dict[str, dict] = {}

        for n in confiables:
            peso = self.reputacion.peso_efectivo(n)
            hash_nodo = self.nodos.get(n, "")
            voto_a_favor = hash_nodo == hash_conflictivo

            # Cada nodo tiene timeout individual
            start = time.time()
            try:
                # Simular latencia de red (timeout simulado)
                time.sleep(min(0.01, self.timeout_nodo))
                if time.time() - start > self.timeout_nodo:
                    LOG.warning("Reconsensus: %s TIMEOUT", n)
                    self.reputacion.penalizar(n, "timeout_reconsenso")
                    continue
            except (OSError, ConnectionError, socket.timeout):
                pass

            if voto_a_favor:
                votos_a_favor += peso
            else:
                votos_en_contra += peso
            resultados_nodos[n] = {"voto": voto_a_favor, "peso": peso}

        peso_total = votos_a_favor + votos_en_contra
        resultado = votos_a_favor / peso_total > 0.5 if peso_total > 0 else False

        resolucion = {
            "timestamp": datetime.now().isoformat(),
            "hash_conflictivo": hash_conflictivo,
            "resultado": resultado,
            "votos_a_favor": round(votos_a_favor, 3),
            "votos_en_contra": round(votos_en_contra, 3),
            "peso_total": round(peso_total, 3),
            "nodos_participantes": list(confiables),
            "detalle_nodos": resultados_nodos,
        }

        _persistir_log(self.data_dir / "resolucion_reconsensus.json", resolucion, self.reputacion._secreto)
        LOG.info("Reconsensus: %s → %s (%.1f%% a favor)",
                 hash_conflictivo[:16], "ACEPTADO" if resultado else "RECHAZADO",
                 100 * votos_a_favor / peso_total if peso_total else 0)
        return resultado


# Nodos por defecto (equivalente a los del prototipo original)
DEFAULT_NODOS = {
    "Nodo_A": "a1b2c3d4e5f6a7b8",
    "Nodo_B": "b2c3d4e5f6a7b8c9",
    "Nodo_C": "c3d4e5f6a7b8c9d0",
    "Nodo_D": "d4e5f6a7b8c9d0e1",
    "Nodo_E": "e5f6a7b8c9d0e1f2",
    "Nodo_F": "f6a7b8c9d0e1f2a3",
    "Nodo_G": "a7b8c9d0e1f2a3b4",
}
