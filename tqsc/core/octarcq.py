"""
TQSC v1.0 — OctaCore: Orquestador de Procesamiento
Contains classes: PersistenceEngineQMem, OctaCore
"""
import logging, json, hmac, hashlib, secrets, time
from pathlib import Path

logger = logging.getLogger("tqsc.ia_core")

from core.octa_nucleo import OctaNucleo, PatternGate, PreImpactSynthesizer, GhostMemoryZone
from core.octa_nucleo import OctaNucleo
from tqsc.classic_crypto import ClassicCryptoCore
from ia import (
    ContextWeaver,
    PredictiveReinforcer,
    ModelTrainer,
    CognitiveLoopDetector,
    MetaCoreAdjuster,
    PatternTransfuser,
    ShadowCloneManager,
    IAJudicialInterna,
    EthicalConsensusGate,
    MutationLogger,
    RCQNeuralShield,
)


class PersistenceEngineQMem:
    """Memoria latente con HMAC por instancia."""

    def __init__(self, data_dir: str = "data"):
        self.ruta = Path(data_dir) / "qmem_state.json"
        self._secreto = secrets.token_hex(16)  # único por instancia

    def guardar(self, nucleo: OctaNucleo):
        datos = nucleo.snapshot()
        raw = json.dumps(datos, sort_keys=True).encode()
        datos["hmac"] = hmac.new(self._secreto.encode(), raw, hashlib.sha256).hexdigest()[:32]
        with open(self.ruta, "w") as f:
            json.dump(datos, f, indent=4)

    def cargar(self, nombre: str) -> dict | None:
        try:
            with open(self.ruta) as f:
                datos = json.load(f)
            hmac_guardado = datos.pop("hmac", None)
            if not hmac_guardado:
                return None
            raw = json.dumps(datos, sort_keys=True).encode()
            esperado = hmac.new(self._secreto.encode(), raw, hashlib.sha256).hexdigest()[:32]
            if not hmac.compare_digest(hmac_guardado, esperado):
                return None
            return datos
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            return None


LOG_IA = logging.getLogger("tqsc.ia_core")

class OctaCore:
    """OctaCore — Procesador principal (antes OctaRCQ-X8)."""
    _OBSOLETO = "OctaRCQX8"  # backward compat
    """Orquestador completo de la IA Autoevolutiva — 18 subnúcleos."""

    def __init__(self, data_dir: str = "data"):
        # 8 octantes cognitivos
        self.octantes = [OctaNucleo(f"O{i+1}", nucleos_hijos=2) for i in range(8)]

        # Módulos de entrada
        self.pattern_gate = PatternGate()
        self.preimpact = PreImpactSynthesizer()
        self.contextualizador = ContextWeaver()
        self.juez = IAJudicialInterna()
        self.validador_cu = ClassicCryptoCore(data_dir=data_dir)

        # Módulos de procesamiento
        self.reinforcer = PredictiveReinforcer()
        self.trainer = ModelTrainer()
        self.loop_detector = CognitiveLoopDetector()
        self.transfuser = PatternTransfuser()
        self.ajustador = MetaCoreAdjuster()
        self.etico = EthicalConsensusGate()
        self.ghost = GhostMemoryZone()
        self.clonador = ShadowCloneManager()
        self.persistencia = PersistenceEngineQMem(data_dir=data_dir)
        self.logger_mut = MutationLogger(data_dir=data_dir)
        self.shields = [RCQNeuralShield(n) for n in self.octantes]

        logger.info("🧬 OctaRCQ-X8: 18 subnúcleos listos")

    def recibir_evento(self, evento: str, entorno: dict | None = None) -> list[str]:
        """Procesa un evento con orden aleatorio de filtros anti-fuzzing."""
        from random import shuffle

        filtros = [
            ("PatternGate", lambda: not self.pattern_gate.validar(evento), LOG_IA.debug, "Bloqueado por PatternGate"),
            ("PreImpact", lambda: self.preimpact.anticipar(evento), LOG_IA.info, "Evacuado por PreImpact"),
            ("IAJudicial", lambda: not self.juez.juzgar(evento), LOG_IA.warning, "Bloqueado por IA Judicial"),
        ]
        shuffle(filtros)
        for nombre, fn, log_fn, msg in filtros:
            if fn():
                self.ghost.evacuar(evento)
                log_fn("%s: %.60s", msg, evento)
                return []

        # Filtro 4: Validación Cuántica
        evento_dict = {"timestamp": time.time(), "origen": "octarcq", "tipo": "evento",
                       "hash": hashlib.sha256(evento.encode()).hexdigest(), "firma": "tqsc"}
        resultado_q = self.validador_cu.procesar(evento_dict)
        if "Descartado" in resultado_q or "Falso" in resultado_q:
            self.ghost.evacuar(evento)
            LOG_IA.info("Bloqueado por Quantum: %.60s → %s", evento, resultado_q)
            return []

        # Contextualizar y distribuir a todos los octantes (round-robin)
        contexto = self.contextualizador.fusionar(evento, entorno or {})
        aceptados = []
        for i, nucleo in enumerate(self.octantes):
            if nucleo.estado == "activo":
                nucleo.recibir(str(contexto))
                aceptados.append(evento)
                if len(aceptados) >= 3:  # máx 3 confirmaciones
                    break
        return aceptados

    def rotar(self):
        """Ciclo de procesamiento completo — entrenamiento, refuerzo, ajuste, persistencia."""
        for nucleo in self.octantes:
            self.loop_detector.evaluar(nucleo)
            self.trainer.entrenar(nucleo)
            self.reinforcer.reforzar(nucleo)
            self.ajustador.ajustar(nucleo)
            self.persistencia.guardar(nucleo)

        # Transferencia entre octantes
        for i in range(len(self.octantes) - 1):
            self.transfuser.transferir(self.octantes[i], self.octantes[i + 1])

        # Escudos neurales
        for escudo in self.shields:
            escudo.evaluar()

        # Shadow clones
        for nucleo in self.octantes:
            if not nucleo.shadow:
                self.clonador.clonar(nucleo)
            self.clonador.restaurar_si_corrupto(nucleo)

        logger.debug(f"OctaRCQ: rotación completa ({len(self.octantes)} núcleos)")

    def estado(self) -> dict:
        return {
            "octantes": [{"nombre": n.nombre, "estado": n.estado, "adn": n.adn_hash[-1] if n.adn_hash else None}
                         for n in self.octantes],
            "ghost_size": len(self.ghost.zona),
        }

# Backward compatibility alias
OctaRCQX8 = OctaCore
