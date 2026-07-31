"""
tqsc/deception/controller.py — Lifecycle manager with DI y health endpoint.
Incluye ABH Engine: Behavioral Honeytoken Engine con profiling adaptativo.
"""
import logging, time
from typing import Optional
from .storage import SQLiteStorage
from .alert_engine import AlertEngine
from .honeytokens import HoneytokenEngine
from .honeyfiles import HoneyFiles
from .honeycreds import HoneyCredentials
from .canary_dns import CanaryDNS
from .canary_http import CanaryHTTP
from .mtd import MovingTargetDefense
from .breadcrumbs import Breadcrumbs
from .fake_ad import FakeActiveDirectory
from .tarpit import Tarpit
# ABH Engine
from .behavioral_profiler import BehavioralProfiler
from .entropy_matcher import EntropyMatcher
from .context_injector import ContextInjector
from .rl_agent import RLAgent
from .llm_generator import LLMTokenGenerator
from .behavioral_honeytokens import BehavioralHoneytokenEngine

LOG = logging.getLogger("tqsc.deception.controller")

CONFIG_DEFAULTS = {
    "tqsc_home": "data", "dns_puerto": 5353, "dns_dominio": "canary.tqsc.internal",
    "http_puerto": 8088, "mtd_intervalo": 300,
}


class DeceptionController:
    """Orquestador profesional con DI. Todos los componentes inyectados."""

    def __init__(self, storage: SQLiteStorage, alerts: AlertEngine, config: dict = None):
        self._storage = storage
        self._alerts = alerts
        self._config = {**CONFIG_DEFAULTS, **(config or {})}
        self._activo = False
        self._health = {"status": "inicializando", "componentes": {}}

        # Instanciar todos los componentes con DI
        self.honeytokens = HoneytokenEngine(storage, alerts, self._config["tqsc_home"])
        self.honeyfiles = HoneyFiles(storage, alerts)
        self.honeycreds = HoneyCredentials(storage, alerts)
        self.canary_dns = CanaryDNS(alerts, self._config["dns_puerto"], self._config["dns_dominio"])
        self.canary_http = CanaryHTTP(alerts, self._config["http_puerto"])
        self.mtd = MovingTargetDefense(self._config["mtd_intervalo"])
        self.breadcrumbs = Breadcrumbs(self._config["tqsc_home"])
        self.fake_ad = FakeActiveDirectory()
        self.tarpit = Tarpit()

        # ── ABH Engine (Behavioral Honeytokens) ──
        abh_mode = self._config.get("abh_llm_mode", "simulated")
        abh_ml = self._config.get("abh_use_ml", True)
        self.abh_engine = BehavioralHoneytokenEngine(
            storage, alerts, 
            tqsc_home=self._config["tqsc_home"],
            use_ml=abh_ml,
            llm_mode=abh_mode,
        )
        # Hooks: conectar ABH al AlertEngine para feedback automático
        alerts.register_hook(self.abh_engine.procesar_feedback_from_alert)

        # Registrar componentes (incluyendo ABH)
        self._componentes = [
            ("honeytokens", self.honeytokens), ("honeyfiles", self.honeyfiles),
            ("honeycreds", self.honeycreds), ("canary_dns", self.canary_dns),
            ("canary_http", self.canary_http), ("mtd", self.mtd),
            ("breadcrumbs", self.breadcrumbs), ("fake_ad", self.fake_ad),
            ("tarpit", self.tarpit),
            ("abh_engine", self.abh_engine),  # <-- NUEVO
        ]

    def _iniciar(self):
        """Inicia todos los componentes con try/except individual."""
        # Honeytokens legacy (estáticos) — mantener compatibilidad
        self.honeytokens.generar("aws_key", "~/.aws/credentials", "AWS")
        self.honeytokens.generar("jwt", "config/token.jwt", "JWT")
        self.honeytokens.generar("db_string", ".env", "DB")

        # ABH: no genera tokens estáticos, espera eventos
        # Profiler y RL agent están listos para recibir telemetría

        self.honeyfiles.plantar()

        for nombre, inst in self._componentes:
            if not hasattr(inst, "iniciar"):
                self._health["componentes"][nombre] = "ok"
                continue
            try:
                inst.iniciar()
                self._health["componentes"][nombre] = "ok"
                LOG.info("  ✅ %s iniciado", nombre)
            except Exception as e:
                self._health["componentes"][nombre] = f"fallo: {e}"
                LOG.warning("  ⚠️ %s: %s", nombre, e)

    def iniciar(self) -> dict:
        if self._activo:
            return self._health
        self._activo = True
        try:
            self._iniciar()
        except Exception as e:
            LOG.error("Deception iniciar: %s", e)
        self._health["status"] = "activo"
        self._health["timestamp"] = time.time()
        ok = sum(1 for v in self._health["componentes"].values() if v == "ok")
        LOG.info("🕸️ Deception activo: %d/%d componentes", ok, len(self._componentes))
        return self._health

    def detener(self):
        self._activo = False
        for nombre, inst in reversed(self._componentes):
            if hasattr(inst, "detener"):
                try:
                    inst.detener()
                except Exception as e:
                    LOG.error("Error al detener %s: %s", nombre, e)
        self._health["status"] = "detenido"
        self._storage.cerrar()

    def health(self) -> dict:
        ok = sum(1 for v in self._health["componentes"].values() if v == "ok")
        return {**self._health, "disponibilidad": f"{ok}/{len(self._componentes)}",
                "uptime": time.time() - self._health.get("timestamp", time.time())}

    def metricas(self) -> dict:
        base = {"alertas_24h": self._alerts.contar(time.time() - 86400),
                "componentes_ok": sum(1 for v in self._health["componentes"].values() if v == "ok"),
                "componentes_total": len(self._componentes)}
        # ABH metrics
        try:
            base["abh"] = self.abh_engine.metricas()
        except Exception:
            base["abh"] = {"error": "no_disponible"}
        return base
