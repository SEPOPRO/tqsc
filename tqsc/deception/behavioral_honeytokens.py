"""
tqsc/deception/behavioral_honeytokens.py — BehavioralHoneytokenEngine.
Motor principal del ABH Engine. Reemplaza a HoneytokenEngine existente.

Pipeline:
  1. Telemetría del honeypot → BehavioralProfiler (TTPs + perfil + intención)
  2. RL Agent decide qué token generar según el estado del perfil
  3. LLM Generator crea el token personalizado para este atacante
  4. Entropy Matcher verifica que el token sea estadísticamente realista
  5. Context Injector decide dónde plantarlo
  6. Feedback loop: interacción → recompensa RL → mejora continua
"""
import logging, time, json, threading
from pathlib import Path
from typing import Optional

from .interfaces import ITokenGenerator
from .models import Token
from .storage import SQLiteStorage
from .alert_engine import AlertEngine
from .behavioral_profiler import BehavioralProfiler
from .entropy_matcher import EntropyMatcher
from .context_injector import ContextInjector
from .rl_agent import RLAgent
from .llm_generator import LLMTokenGenerator

LOG = logging.getLogger("tqsc.deception.behavioral_honeytokens")


class BehavioralHoneytokenEngine(ITokenGenerator):
    """Motor ABH completo. Implementa ITokenGenerator para ser
    compatible con el orquestador DeceptionController existente.

    Uso:
        engine = BehavioralHoneytokenEngine(storage, alerts, tqsc_home="data")
        engine.iniciar()
        token = engine.generar()  # Generación adaptativa
        engine.procesar_feedback(session_id, interacted=True)
    """

    def __init__(self, storage: SQLiteStorage, alerts: AlertEngine,
                 tqsc_home: str = "data", use_ml: bool = True,
                 llm_mode: str = "simulated"):
        self._storage = storage
        self._alerts = alerts
        self._tqsc_home = Path(tqsc_home)
        self._llm_mode = llm_mode
        self._activo = False
        self._lock = threading.Lock()

        # ── Sub-sistemas ABH ──
        self.profiler = BehavioralProfiler(use_ml=use_ml)
        self.entropy_matcher = EntropyMatcher()
        self.context_injector = ContextInjector(tqsc_home=str(self._tqsc_home))
        self.rl_agent = RLAgent()

        # Calibrar EntropyMatcher con datos sintéticos iniciales
        self._calibrate_entropy()

        # Sesiones activas trackeadas por IP
        self._sessions: dict[str, str] = {}

        LOG.info("BehavioralHoneytokenEngine: inicializado "
                 "(llm=%s, ml=%s)", llm_mode, use_ml)

    def _calibrate_entropy(self):
        """Calibra el EntropyMatcher con muestras sintéticas de tokens realistas."""
        real_samples = [
            "postgresql://prod_admin:kV8mP3xR9qL2sT7w@pg-main-01.internal:5432/production",
            "mysql://app_user:Xj5nK9pQ2rM8vB4w@db-cluster.internal:3306/app_prod",
            "AKIA5X2F8K9M3P7Q1R4T",
            "github_pat_11AAABBBCCCDDDEEEFFFGGGHHHIIIJJJKKKLLLMMMNNN000PPP",
            "xoxb-1234567890-1234567890123-ABCDEFGHIJKLMNOPQRST",
            "DOMAIN\\svc_backup_adm:Jf8mK2pR5sW7xZ1q",
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDCx8K9M3P7Q1R4T...",
            "DB_HOST=db-primary.internal\nDB_USER=app_user\nDB_PASS=K9mP3xR7qL2sT8w",
            "monitoring:Wx4pR7sK9mQ2nL5t@monitor-01.internal",
            "root:kV8mP3xR9qL2sT7w@localhost:3306",
            "redis://cache-primary:kV8mP3xR9qL2sT7w@cache-01.internal:6379",
            "mongodb://backup_admin:Wx4pR7sK9mQ2nL5t@mongo-rs.internal:27017/admin",
        ]
        self.entropy_matcher.calibrate(real_samples)

    # ─────────────────────────────────────────────
    # Pipeline principal de generación
    # ─────────────────────────────────────────────

    def generar(self, tipo: str = "", ubicacion: str = "",
                memo: str = "", attacker_ip: str = "",
                attacker_command: str = "", attacker_port: int = 0,
                session_data: dict = None) -> dict:
        """Genera un honeytoken adaptativo basado en el perfil del atacante.

        Args:
            tipo: Tipo de token (opcional — si se omite, RL decide)
            ubicacion: Ubicación (opcional — si se omite, ContextInjector decide)
            memo: Memo descriptivo
            attacker_ip: IP del atacante (para profiling)
            attacker_command: Último comando observado
            attacker_port: Puerto al que se conectó
            session_data: Datos de sesión (user, pass, etc.)

        Returns:
            dict con el token generado + metadatos
        """
        with self._lock:
            return self._generar_interno(tipo, ubicacion, memo,
                                          attacker_ip, attacker_command,
                                          attacker_port, session_data)

    def _generar_interno(self, tipo, ubicacion, memo,
                          attacker_ip, attacker_command,
                          attacker_port, session_data) -> dict:
        """Pipeline interno de 6 pasos."""

        # ── Paso 1: Perfilar al atacante ──
        profile = self.profiler.process_observation(
            ip=attacker_ip or "unknown",
            command=attacker_command or "",
            user=(session_data or {}).get("user", ""),
            password=(session_data or {}).get("pass", ""),
            tool="",
            port=attacker_port,
            session_data=session_data,
        )

        session_id = attacker_ip or f"anon_{time.time()}"

        # ── Paso 2: RL Agent decide qué generar ──
        if not tipo:
            rl_decision = self.rl_agent.start_episode(session_id, profile)
            token_type = rl_decision.get("token_type", "config_file")
            LOG.debug("RL: %s → token_type=%s", session_id, token_type)
        else:
            token_type = tipo
            rl_decision = {"token_type": tipo, "location_bucket": "filesystem_config"}

        # ── Paso 3: LLM genera el token ──
        generator = LLMTokenGenerator(mode=self._llm_mode)
        token_value = generator.generate(token_type, profile)

        # ── Paso 4: Entropy Matcher verifica realismo ──
        validation = self.entropy_matcher.validate(token_value)
        if not validation["pass"]:
            # Ajustar token
            token_value = self.entropy_matcher.adjust(
                token_value,
                llm_adjust_callback=lambda t, v: generator.generate(token_type, profile),
            )
            LOG.info("Entropy ajustado: z=%.2f → %s",
                     validation.get("z_score", 0), token_type)

        # ── Paso 5: Context Injector decide ubicación ──
        if not ubicacion:
            ttp_observed = ""
            if profile and profile.get("ttp_sequence"):
                ttp_observed = profile["ttp_sequence"][-1]

            attacker_path = ""
            if profile and profile.get("commands"):
                # Inferir path del último comando
                last_cmd = profile["commands"][-1] if profile["commands"] else ""
                path_hints = ["/var/www", "/etc", "/home", "/tmp", "/backup",
                              "C:\\Users", "C:\\inetpub", "C:\\Windows"]
                for hint in path_hints:
                    if hint.lower() in last_cmd.lower():
                        attacker_path = hint
                        break

            location_info = self.context_injector.decide_location(
                token_type, attacker_path, ttp_observed, profile)
            deploy_location = location_info["location"]
            location_reason = location_info["reason"]
        else:
            deploy_location = ubicacion
            location_reason = "especificado por el usuario"

        # ── Paso 6: Persistir y retornar ──
        token = Token(
            tipo=token_type,
            valor=token_value,
            ubicacion=deploy_location,
            memo=memo or f"ABH auto: {token_type} para {attacker_ip}",
            creado=time.time(),
        )

        with self._lock:
            self._storage.guardar_token(token)

        # Plantar en disco
        self._plantar(token)

        result = {
            **token.to_dict(),
            "abh_metadata": {
                "profile_danger": round(profile.get("danger_score", 0), 2) if profile else 0,
                "entropy_validated": validation["pass"],
                "entropy_score": round(validation.get("entropy", 0), 4),
                "location_confidence": location_info.get("confidence", 0) if not ubicacion else 1.0,
                "rl_action": rl_decision,
                "ttp_observed": profile.get("ttp_sequence", [])[-1:] if profile and profile.get("ttp_sequence") else [],
                "intent": profile.get("intent_prediction", {}) if profile else {},
            }
        }

        LOG.info("🎯 ABH honeytoken generado: tipo=%s para %s (danger=%.2f)",
                 token_type, attacker_ip or "unknown",
                 result["abh_metadata"]["profile_danger"])
        return result

    # ─────────────────────────────────────────────
    # Feedback loop
    # ─────────────────────────────────────────────

    def procesar_feedback(self, attacker_ip: str, token_id: str = "",
                           interacted: bool = False, detected: bool = False,
                           time_delayed: float = 0.0,
                           intel_quality: float = 0.0):
        """Procesa feedback de la interacción con un honeytoken.
        Actualiza el RL Agent y refina el perfil del atacante."""
        session_id = attacker_ip or f"anon_{time.time()}"

        profile = self.profiler.get_profile(attacker_ip) or {}

        reward = self.rl_agent.process_feedback(
            session_id, profile,
            token_interacted=interacted,
            token_detected=detected,
            time_delayed=time_delayed,
            intel_quality=intel_quality,
        )

        LOG.info("🔄 Feedback: %s interacted=%s detected=%s reward=%.3f",
                 attacker_ip, interacted, detected, reward)

        if token_id:
            self._storage.actualizar_estado(token_id, "disparado" if interacted else "ignorado")

        return reward

    def procesar_feedback_from_alert(self, alerta: dict):
        """Procesa feedback desde el AlertEngine (hook automático)."""
        detalle = alerta.get("detalle", "")
        ip = alerta.get("ip", "unknown")
        self.procesar_feedback(
            attacker_ip=ip,
            token_id=alerta.get("token_id"),
            interacted=True,
            detected=False,
            time_delayed=alerta.get("tiempo_analisis", 30),
            intel_quality=0.5,
        )

    # ─────────────────────────────────────────────
    # ITokenGenerator interface
    # ─────────────────────────────────────────────

    def verificar(self, valor: str) -> Optional[dict]:
        """Verifica si un valor coincide con algún honeytoken activo."""
        with self._lock:
            cur = self._storage._con.execute(
                "SELECT id, tipo, ubicacion, disparado, valor FROM tokens WHERE valor=? AND disparado=0",
                (valor,))
            row = cur.fetchone()
            if row:
                self._storage._con.execute("UPDATE tokens SET disparado=1 WHERE id=?", (row[0],))
                self._storage._con.commit()

                # Extraer IP del token si está en ubicacion o memo
                ip = ""
                alerta = {
                    "tipo": "honeytoken",
                    "componente": "abh_engine",
                    "detalle": f"Token {row[1]} usado desde {row[2]}",
                    "severidad": "critica",
                    "ip": ip,
                    "token_id": row[0],
                    "tiempo_analisis": 30,
                }
                self._alerts.disparar(alerta)
                LOG.critical("🚨 ABH HONEYTOKEN DISPARADO: %s (%s)", row[1], row[2])

                # Feedback automático
                self.procesar_feedback_from_alert(alerta)
                return alerta
        return None

    def _plantar(self, t: Token):
        """Planta el token en disco (compatible con HoneytokenEngine existente)."""
        nombres = {
            "db_creds": ".env",
            "aws_key": ".aws/credentials",
            "jwt": ".config/token.jwt",
            "ad_creds": ".config/ad_creds.txt",
            "github_token": ".config/github.env",
            "slack_token": ".config/slack.env",
            "ssh_key": ".ssh/id_rsa",
            "config_file": ".config/app_config.ini",
        }
        nombre = nombres.get(t.tipo, f".config/{t.tipo}.txt")
        try:
            ruta = self._tqsc_home / nombre
            ruta.parent.mkdir(parents=True, exist_ok=True)
            ruta.write_text(t.valor + "\n")
            LOG.info("📝 ABH plantado: %s", ruta)
        except (OSError, PermissionError):
            LOG.warning("No se pudo plantar token en %s", nombre)

    # ─────────────────────────────────────────────
    # Lifecycle
    # ─────────────────────────────────────────────

    def iniciar(self):
        """Inicia el motor ABH."""
        self._activo = True
        LOG.info("ABH Engine: activo — tracking perfiles en tiempo real")

    def detener(self):
        """Detiene el motor ABH."""
        self._activo = False
        # Finalizar episodios activos de RL
        active = self._sessions.copy()
        for ip, sid in active.items():
            self.rl_agent.end_episode(sid)
        self._sessions.clear()
        LOG.info("ABH Engine: detenido")

    def estado(self) -> dict:
        """Estado completo del motor ABH."""
        return {
            "activo": self._activo,
            "profiler": self.profiler.estado(),
            "rl_agent": self.rl_agent.estado(),
            "entropy_matcher": self.entropy_matcher.estado(),
            "context_injector": self.context_injector.estado(),
        }

    def metricas(self) -> dict:
        """Métricas de rendimiento del ABH."""
        return {
            "perfiles_activos": self.profiler.count_active(),
            "sesiones_rl": len(self._sessions),
            "total_ttps_observadas": sum(
                self.profiler.ttp_classifier.stats().values()),
            "episodios_rl": self.rl_agent.policy.episode_count,
            "reward_total": round(self.rl_agent.policy.total_reward, 2),
        }
