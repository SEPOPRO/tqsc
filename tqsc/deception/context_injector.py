"""
tqsc/deception/context_injector.py — Context Injector del ABH Engine.
Decide DÓNDE plantar cada honeytoken basado en:
- Posición actual del atacante en el sistema de archivos/red
- Sus TTPs observadas (¿qué está buscando?)
- El tipo de token generado
- Perfil de la organización (¿dónde SON creíbles estos tokens?)
"""
import logging, os, secrets, json
from pathlib import Path
from typing import Optional

LOG = logging.getLogger("tqsc.deception.context_injector")

# Mapa: tipo de token → ubicaciones creíbles según TTP del atacante
TOKEN_LOCATIONS = {
    # Credenciales de base de datos
    "db_creds": {
        "locations": [
            "/var/www/html/config/database.php",
            "/var/www/html/.env",
            "/home/deploy/.pgpass",
            "/etc/mysql/my.cnf",
            "/opt/app/config/database.yml",
            "C:\\inetpub\\wwwroot\\web.config",
            "C:\\Program Files\\app\\connectionstrings.config",
        ],
        "ttp_triggers": ["T1190", "T1046", "T1210"],
        "description": "Credenciales de base de datos en config files",
    },
    # AWS Keys
    "aws_key": {
        "locations": [
            "~/.aws/credentials",
            "/home/deploy/.aws/credentials",
            "/opt/app/.aws/credentials",
            "/var/www/html/.env",
            "C:\\Users\\svc_app\\.aws\\credentials",
        ],
        "ttp_triggers": ["T1525", "T1552"],
        "description": "AWS access keys en config",
    },
    # JWT Token
    "jwt": {
        "locations": [
            "/opt/app/config/token.jwt",
            "/var/www/html/.env",
            "/home/api/.config/token.jwt",
            "C:\\ProgramData\\app\\tokens\\service.jwt",
        ],
        "ttp_triggers": ["T1552", "T1528"],
        "description": "JWT service token",
    },
    # AD Credentials
    "ad_creds": {
        "locations": [
            "/var/lib/samba/private/secrets.ldb",
            "/home/backup/creds.txt",
            "/root/notes/ad_passwords.txt",
            "C:\\Windows\\Tasks\\backup_creds.txt",
            "C:\\temp\\ad_passwords.txt",
        ],
        "ttp_triggers": ["T1003", "T1558", "T1552"],
        "description": "Active Directory credentials",
    },
    # GitHub Token
    "github_token": {
        "locations": [
            "/home/deploy/.config/gh/hosts.yml",
            "/opt/app/.npmrc",
            "/var/www/html/.env",
            "/home/deploy/.git-credentials",
            "C:\\Users\\developer\\.config\\gh\\hosts.yml",
        ],
        "ttp_triggers": ["T1552", "T1525"],
        "description": "GitHub personal access token",
    },
    # Slack Token
    "slack_token": {
        "locations": [
            "/home/deploy/.config/slack.env",
            "/opt/app/.env",
            "/var/www/html/.env",
            "C:\\Users\\developer\\.config\\slack.env",
        ],
        "ttp_triggers": ["T1552"],
        "description": "Slack API token",
    },
    # SSH Key
    "ssh_key": {
        "locations": [
            "/home/deploy/.ssh/id_rsa",
            "/root/.ssh/id_rsa",
            "/home/backup/.ssh/id_rsa",
            "/opt/app/.ssh/id_rsa",
            "C:\\Users\\administrator\\.ssh\\id_rsa",
        ],
        "ttp_triggers": ["T1552", "T1078"],
        "description": "SSH private key",
    },
    # Generic config file
    "config_file": {
        "locations": [
            "/backup/config.ini",
            "/tmp/config_backup.json",
            "/var/backups/app_config.json",
            "C:\\backup\\config.ini",
        ],
        "ttp_triggers": ["T1046", "T1190"],
        "description": "Config file genérico con credenciales",
    },
}

# Mapa: ubicación del atacante → mejor tipo de token
ATTACKER_PATH_TO_TOKEN = {
    "www": ["db_creds", "jwt", "github_token", "config_file"],
    "html": ["db_creds", "jwt", "github_token", "config_file"],
    "config": ["db_creds", "jwt", "slack_token", "aws_key"],
    ".aws": ["aws_key"],
    ".ssh": ["ssh_key"],
    ".git": ["github_token"],
    "backup": ["db_creds", "ssh_key", "config_file"],
    "deploy": ["ssh_key", "aws_key", "github_token"],
    "app": ["db_creds", "jwt", "config_file"],
    "etc": ["db_creds", "config_file"],
    "root": ["ssh_key", "ad_creds"],
    "admin": ["ad_creds", "ssh_key"],
    "temp": ["ad_creds", "config_file"],
    "ProgramData": ["ad_creds", "jwt"],
}

# Mapa: TTP observada → mejor tipo de token
TTP_TO_TOKEN = {
    "T1190": "db_creds",       # SQL Injection → creds DB
    "T1046": "config_file",     # Network Scanning → archivos de config
    "T1003": "ad_creds",        # Credential Dumping → AD creds
    "T1558": "ad_creds",        # Kerberoasting → SPN + creds AD
    "T1525": "aws_key",         # Cloud Credential Theft → AWS keys
    "T1552": "jwt",             # Unsecured Credentials → tokens
    "T1078": "ssh_key",         # Valid Accounts → SSH keys
    "T1210": "db_creds",        # Exploit of Remote Services → DB
    "T1528": "jwt",             # Steal App Access Token → JWT
}


class ContextInjector:
    """Decide la ubicación óptima para cada honeytoken basado en
    el contexto del atacante y el perfil de la organización."""

    def __init__(self, tqsc_home: str = "data"):
        self._tqsc_home = Path(tqsc_home)
        self._org_profile: dict = {}
        self._deployed: list[dict] = []

    def set_org_profile(self, profile: dict):
        """Configura el perfil de la organización (paths reales, servicios, etc.)."""
        self._org_profile = profile

    def decide_location(self, token_type: str, attacker_position: str = "",
                        ttp_observed: str = "", profile: Optional[dict] = None) -> dict:
        """Decide la mejor ubicación para plantar el token.

        Args:
            token_type: Tipo de token (db_creds, aws_key, jwt, etc.)
            attacker_position: Ruta del FS donde está el atacante
            ttp_observed: TTP de MITRE ATT&CK observada
            profile: Perfil del atacante (opcional, enriquece decisión)

        Returns:
            dict con {location, reason, confidence}
        """
        candidates = TOKEN_LOCATIONS.get(token_type, {}).get("locations", [])
        if not candidates:
            # Fallback: token genérico
            candidates = [f"/tmp/.secret_{secrets.token_hex(4)}",
                          f"/var/tmp/.config_{secrets.token_hex(4)}"]

        score_map = []

        for loc in candidates:
            score = 0.0
            reasons = []

            # 1. ¿La ubicación del atacante coincide con este path?
            if attacker_position:
                path_match = self._path_similarity(attacker_position, loc)
                score += path_match * 0.4
                if path_match > 0.5:
                    reasons.append(f"atacante cerca de {attacker_position}")

            # 2. ¿La TTP observada coincide con este tipo de token?
            expected_type = TTP_TO_TOKEN.get(ttp_observed, "")
            if expected_type == token_type:
                score += 0.3
                reasons.append(f"TTP {ttp_observed} → {token_type}")

            # 3. ¿Esta ubicación es creíble según el perfil de la organización?
            if self._org_profile:
                org_match = self._org_check(loc)
                if org_match > 0:
                    score += org_match * 0.2
                    reasons.append("consistente con perfil organizacional")

            # 4. Penalizar si ya se desplegó un token similar en esta ubicación
            if any(d.get("location") == loc and d.get("type") == token_type
                   for d in self._deployed):
                score -= 0.5
                reasons.append("ya usado (penalizado)")

            score_map.append((loc, max(0.0, min(1.0, score)), reasons))

        if not score_map:
            return {"location": candidates[0], "reason": "default",
                    "confidence": 0.1}

        # Elegir la mejor opción
        best = max(score_map, key=lambda x: x[1])
        selected = {
            "location": best[0],
            "confidence": round(best[1], 2),
            "reason": "; ".join(best[2]) if best[2] else "default",
        }

        # Registrar deployment
        self._deployed.append({"type": token_type, "location": best[0],
                               "timestamp": __import__("time").time()})
        return selected

    def _path_similarity(self, attacker_pos: str, candidate: str) -> float:
        """Mide qué tan cerca está el atacante de la ubicación candidata."""
        a_parts = set(attacker_pos.replace("\\", "/").lower().split("/"))
        c_parts = set(candidate.replace("\\", "/").lower().split("/"))

        if not a_parts or not c_parts:
            return 0.0

        intersection = a_parts & c_parts
        union = a_parts | c_parts

        # Jaccard similarity sobre los componentes del path
        jaccard = len(intersection) / len(union) if union else 0.0

        # Bonus si comparten directorios padres
        for i in range(1, min(len(a_parts), len(c_parts)) + 1):
            a_prefix = "/".join(list(a_parts)[:i])
            c_prefix = "/".join(list(c_parts)[:i])
            if a_prefix == c_prefix:
                jaccard += 0.1

        return min(1.0, jaccard)

    def _org_check(self, location: str) -> float:
        """Verifica consistencia con el perfil organizacional."""
        score = 0.0
        org_paths = self._org_profile.get("paths", [])
        org_services = self._org_profile.get("services", [])

        for op in org_paths:
            if op.lower() in location.lower():
                score += 0.5

        for svc in org_services:
            if svc.lower() in location.lower():
                score += 0.3

        return min(1.0, score)

    def decide_token_type(self, ttp_observed: str, attacker_path: str = "",
                          profile: Optional[dict] = None) -> str:
        """Decide qué tipo de token generar dado el contexto del atacante."""
        # 1. Por TTP
        if ttp_observed in TTP_TO_TOKEN:
            return TTP_TO_TOKEN[ttp_observed]

        # 2. Por path del atacante
        if attacker_path:
            for path_key, tokens in ATTACKER_PATH_TO_TOKEN.items():
                if path_key in attacker_path.lower():
                    return tokens[0]

        # 3. Por perfil (si tiene preferencias conocidas)
        if profile:
            targets = profile.get("target_preference", {})
            protocols = targets.get("protocols", [])
            if "MSSQL" in protocols or "MySQL" in protocols or "SQL" in str(protocols):
                return "db_creds"
            if "LDAP" in protocols or "AD" in str(protocols):
                return "ad_creds"
            if "cloud" in str(protocols) or "AWS" in str(protocols):
                return "aws_key"

        # 4. Default: lo más versátil
        return "db_creds"

    def clear_history(self):
        """Limpia el historial de deployments (para reset de sesión)."""
        self._deployed.clear()

    def estado(self) -> dict:
        return {
            "deployments": len(self._deployed),
            "org_profile_loaded": bool(self._org_profile),
            "token_types_available": list(TOKEN_LOCATIONS.keys()),
        }
