"""
tqsc/deception/llm_generator.py — LLM Token Generator del ABH Engine.
Default mode: simulated (string templates). Optional LLM mode requires llama-cpp-python. Optional API mode requires external endpoint.
"""
import logging, secrets, json, base64, hashlib, hmac, time, string
from typing import Optional, Callable

LOG = logging.getLogger("tqsc.deception.llm_generator")

# Tokens sintéticos realistas para diferentes tipos
SAMPLE_TOKENS = {
    "db_creds": [
        "postgresql://deploy_admin:{pw}@pg-main-01.internal:5432/production_db",
        "mysql://app_user:{pw}@db-primary.cluster.internal:3306/app_prod",
        "mssql://svc_replication:{pw}@sql-02.corp.local:1433/DataWarehouse",
        "mongodb://backup_user:{pw}@mongo-rs-01.internal:27017/admin",
    ],
    "aws_key": [
        "AKIA{pw}",
    ],
    "jwt": [
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{payload}.{sig}",
    ],
    "ad_creds": [
        "DOMAIN\\svc_backup_adm:{pw}",
        "DOMAIN\\sql_replication:{pw}",
        "DOMAIN\\monitoring_svc:{pw}",
        "DOMAIN\\automation_user:{pw}",
    ],
    "github_token": [
        "github_pat_{pw}",
    ],
    "slack_token": [
        "xoxb-{pw}",
    ],
    "ssh_key": [
        "-----BEGIN OPENSSH PRIVATE KEY-----\n{pw}\n-----END OPENSSH PRIVATE KEY-----",
    ],
    "config_file": [
        "DB_HOST=db-primary.internal\nDB_USER=app\nDB_PASS={pw}\nDB_NAME=production",
        "API_KEY={pw}\nAPI_SECRET={pw}\nAPI_ENDPOINT=https://api.internal.corp",
    ],
}


class LLMTokenGenerator:
    """Generador de honeytokens usando LLM (Mistral 7B) o modo simulado.

    Modos:
    - 'simulated': usa templates con secrets (no requiere GPU)
    - 'llm': carga modelo GGUF cuantizado (requiere llama-cpp-python)
    - 'api': conecta a API externa (OpenAI-compatible)
    """

    def __init__(self, mode: str = "simulated", model_path: str = "",
                 api_endpoint: str = "", api_key: str = ""):
        self.mode = mode
        self.model_path = model_path
        self.api_endpoint = api_endpoint
        self.api_key = api_key
        self._model = None
        self._token_count = 0
        self._generation_stats = {"total": 0, "avg_entropy": 0.0}

        if mode == "llm":
            self._init_llm()
        elif mode == "api":
            LOG.info("LLMGenerator: modo API — %s", api_endpoint or "no configurado")
        else:
            LOG.info("LLMGenerator: modo simulado (sin GPU)")

    def _init_llm(self):
        """Inicializa modelo GGUF cuantizado o transformers local."""
        self.is_transformers = False
        try:
            from llama_cpp import Llama
            self._model = Llama(
                model_path=self.model_path if self.model_path else "dummy.gguf",
                n_ctx=2048,
                n_threads=4,
                n_gpu_layers=-1,  # Todos los layers en GPU si disponible
                verbose=False,
            )
            LOG.info("LLMGenerator: modelo GGUF cargado desde %s", self.model_path)
        except ImportError:
            try:
                import torch
                from transformers import pipeline
                model_name = self.model_path if self.model_path else "gpt2"
                self._model = pipeline("text-generation", model=model_name)
                self.is_transformers = True
                LOG.info(f"LLMGenerator: modelo transformers '{model_name}' cargado")
            except Exception as e:
                LOG.warning(f"LLMGenerator: error cargando transformers — {e}")
                self.mode = "simulated"
        except Exception as e:
            LOG.warning(f"LLMGenerator: error cargando modelo — {e}")
            self.mode = "simulated"

    def _build_prompt(self, token_type: str, profile: dict = None,
                      context: dict = None) -> str:
        """Construye el prompt para el LLM basado en el perfil del atacante."""
        target_info = ""
        if profile:
            ttps = profile.get("ttp_sequence", [])
            tools = profile.get("tooling", [])
            target_info = f"""
## Profile del Atacante
- TTPs observadas: {', '.join(ttps[-5:]) if ttps else 'ninguna'}
- Tooling detectado: {', '.join(tools) if tools else 'desconocido'}
- Peligrosidad: {profile.get('danger_score', 0):.1f}/1.0
- Sesiones: {profile.get('session_count', 0)}
"""

        prompt = f"""Genera un honeytoken de tipo '{token_type}' que parezca real.

{target_info}

## Reglas de Generación
1. El token debe ser indistinguible de un token real de producción
2. Usa nombres de servicios, users y dominios creíbles
3. NO uses palabras como "fake", "test", "honeypot", "canary", "decoy"
4. Incluye comentarios o contexto si es un archivo de configuración
5. Los valores sensibles deben verse como credenciales reales
6. La entropía debe coincidir con la de un entorno productivo

## Output
Genera SOLO el contenido del token, sin explicaciones adicionales.
"""
        return prompt

    def generate(self, token_type: str, profile: dict = None,
                 context: dict = None, entropy_adjust: bool = True) -> str:
        """Genera un honeytoken del tipo especificado.

        Args:
            token_type: Tipo de token (db_creds, aws_key, jwt, etc.)
            profile: Perfil del atacante (opcional, personaliza la generación)
            context: Contexto adicional (entorno, path, etc.)
            entropy_adjust: Si True, el token generado tendrá entropía variable

        Returns:
            Token generado como string
        """
        self._token_count += 1

        if self.mode == "simulated":
            return self._generate_simulated(token_type, profile, entropy_adjust)
        elif self.mode == "llm" and self._model:
            return self._generate_llm(token_type, profile, context)
        elif self.mode == "api":
            return self._generate_api(token_type, profile, context)
        else:
            return self._generate_simulated(token_type, profile, entropy_adjust)

    def _generate_simulated(self, token_type: str, profile: dict = None,
                             entropy_adjust: bool = True) -> str:
        """Genera token simulado con templates y secrets."""
        templates = SAMPLE_TOKENS.get(token_type, SAMPLE_TOKENS["config_file"])
        template = secrets.choice(templates)

        # Generar componentes del token
        pw_length = secrets.choice(range(16, 40))
        pw = secrets.token_urlsafe(pw_length)

        if token_type == "jwt":
            header = base64.urlsafe_b64encode(
                json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
            ).rstrip(b"=").decode()
            payload_data = {
                "sub": f"svc_{secrets.token_hex(4)}",
                "role": secrets.choice(["admin", "readonly", "deploy", "monitor"]),
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600,
            }
            payload = base64.urlsafe_b64encode(
                json.dumps(payload_data).encode()
            ).rstrip(b"=").decode()
            sig = base64.urlsafe_b64encode(
                hmac.new(secrets.token_bytes(32),
                         f"{header}.{payload}".encode(),
                         hashlib.sha256).digest()
            ).rstrip(b"=").decode()
            token = f"{header}.{payload}.{sig}"
        elif token_type == "aws_key":
            key_id = "AKIA" + secrets.token_hex(8).upper()[:16]
            token = f"[default]\naws_access_key_id={key_id}\naws_secret_access_key={base64.b64encode(secrets.token_bytes(30)).decode()}"
        elif token_type == "github_token":
            token = f"github_pat_{secrets.token_hex(22)}_{secrets.token_hex(38)}"
        elif token_type == "slack_token":
            token = f"xoxb-{secrets.randbits(32)}-{secrets.randbits(48)}-{secrets.token_hex(16)}"
        elif token_type == "ssh_key":
            key_body = base64.b64encode(secrets.token_bytes(64)).decode()
            token = f"-----BEGIN OPENSSH PRIVATE KEY-----\n{key_body}\n-----END OPENSSH PRIVATE KEY-----"
        elif token_type == "ad_creds":
            user = secrets.choice(["svc_backup", "sql_replication", "monitoring",
                                    "automation", "sccm_admin", "wsus_sync"])
            token = f"DOMAIN\\{user}:{secrets.token_urlsafe(16)}"
        elif token_type == "config_file":
            token = (f"DB_HOST={secrets.choice(['db-primary', 'pg-main', 'sql-cluster'])}"
                     f".internal\nDB_PORT=5432\nDB_USER={secrets.token_hex(4)}_app\n"
                     f"DB_PASS={secrets.token_urlsafe(20)}\nDB_NAME=production")
        else:
            # db_creds u otros
            token = template.replace("{pw}", secrets.token_urlsafe(pw_length))

        # Registrar estadísticas de entropía
        self._update_stats(token)

        return token

    def _generate_llm(self, token_type: str, profile: dict = None,
                       context: dict = None) -> str:
        """Genera token usando el LLM local."""
        prompt = self._build_prompt(token_type, profile, context)
        try:
            if getattr(self, "is_transformers", False):
                response = self._model(prompt, max_new_tokens=100, num_return_sequences=1,
                                       temperature=0.8, top_p=0.9, do_sample=True,
                                       truncation=True)
                token = response[0]["generated_text"][len(prompt):].strip()
            else:
                response = self._model.create_completion(
                    prompt,
                    max_tokens=512,
                    temperature=0.8,
                    top_p=0.9,
                    stop=["\n\n\n"],
                )
                token = response["choices"][0]["text"].strip()
                
            if not token:
                raise ValueError("Empty token generated")
        except Exception as e:
            LOG.error("LLM generation error: %s", e)
            token = self._generate_simulated(token_type, profile)

        self._update_stats(token)
        return token

    def _generate_api(self, token_type: str, profile: dict = None,
                       context: dict = None) -> str:
        """Genera token via API OpenAI-compatible."""
        import requests

        prompt = self._build_prompt(token_type, profile, context)
        headers = {"Authorization": f"Bearer {self.api_key}",
                   "Content-Type": "application/json"}

        try:
            resp = requests.post(
                self.api_endpoint or "https://api.openai.com/v1/completions",
                headers=headers,
                json={
                    "model": "gpt-4o-mini",
                    "prompt": prompt,
                    "max_tokens": 256,
                    "temperature": 0.8,
                },
                timeout=10,
            )
            if resp.ok:
                token = resp.json()["choices"][0]["text"].strip()
            else:
                token = self._generate_simulated(token_type, profile)
        except Exception as e:
            LOG.warning("LLM API error: %s — fallback simulado", e)
            token = self._generate_simulated(token_type, profile)

        self._update_stats(token)
        return token

    def _update_stats(self, token: str):
        """Actualiza estadísticas de generación."""
        h = self._estimate_entropy(token)
        total = self._generation_stats["total"]
        avg = self._generation_stats["avg_entropy"]
        self._generation_stats["avg_entropy"] = (avg * total + h) / (total + 1)
        self._generation_stats["total"] = total + 1

    @staticmethod
    def _estimate_entropy(text: str) -> float:
        """Estimación rápida de entropía."""
        if not text:
            return 0.0
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        n = len(text)
        import math
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    def generate_batch(self, token_type: str, count: int = 5,
                       profile: dict = None) -> list[str]:
        """Genera múltiples tokens del mismo tipo."""
        return [self.generate(token_type, profile) for _ in range(count)]

    def estado(self) -> dict:
        return {
            "mode": self.mode,
            "tokens_generated": self._generation_stats["total"],
            "avg_entropy": round(self._generation_stats["avg_entropy"], 2),
            "model_loaded": self._model is not None,
        }
