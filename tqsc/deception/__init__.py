"""\ntqsc/deception/__init__.py — Paquete profesional de Deception Mesh TQSC.\n18+ modulos con DI, SQLite persistente, event sourcing, MITRE mapping.\nIncluye ABH Engine: Behavioral Profiler, LLM Generator, Entropy Matcher,\nContext Injector, RL Agent y Behavioral Honeytoken Engine.\n"""
from .controller import DeceptionController
from .storage import SQLiteStorage
from .alert_engine import AlertEngine, MITRE_MAP
from .models import Token, Alerta, EventoCorrelacion

# Componentes
from .honeytokens import HoneytokenEngine
from .honeyfiles import HoneyFiles
from .honeycreds import HoneyCredentials
from .canary_dns import CanaryDNS
from .canary_http import CanaryHTTP
from .mtd import MovingTargetDefense
from .breadcrumbs import Breadcrumbs
from .fake_ad import FakeActiveDirectory
from .tarpit import Tarpit

# ABH Engine (Behavioral Honeytoken Engine)
from .behavioral_profiler import BehavioralProfiler, TTPClassifier, AttackerProfileMatrix, IntentPredictor
from .entropy_matcher import EntropyMatcher
from .context_injector import ContextInjector
from .rl_agent import RLAgent
from .llm_generator import LLMTokenGenerator
from .behavioral_honeytokens import BehavioralHoneytokenEngine

__all__ = [
    "DeceptionController", "SQLiteStorage", "AlertEngine",
    "HoneytokenEngine", "HoneyFiles", "HoneyCredentials",
    "CanaryDNS", "CanaryHTTP", "MovingTargetDefense",
    "Breadcrumbs", "FakeActiveDirectory", "Tarpit",
    "Token", "Alerta", "EventoCorrelacion", "MITRE_MAP",
    # ABH Engine
    "BehavioralProfiler", "TTPClassifier", "AttackerProfileMatrix", "IntentPredictor",
    "EntropyMatcher", "ContextInjector", "RLAgent", "LLMTokenGenerator",
    "BehavioralHoneytokenEngine",
]
