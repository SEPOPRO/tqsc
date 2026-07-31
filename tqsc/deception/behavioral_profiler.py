"""
tqsc/deception/behavioral_profiler.py — Behavioral Profiler del ABH Engine.
Perfila atacantes en tiempo real usando:
- TTP Classifier (Pattern matching against MITRE ATT&CK dictionary)
- Attacker Profile Matrix (In-memory profile storage using Python dicts)
- Intent Predictor (Static transition graph lookup)

Se conecta al pipeline de telemetría del honeypot existente.
"""
import logging, time, json, hashlib, threading
from typing import Optional
from collections import defaultdict, deque

try:
    import torch
    from transformers import AutoTokenizer, AutoModel
    import torch.nn.functional as F
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False

LOG = logging.getLogger("tqsc.deception.behavioral_profiler")

# ──────────────────────────────────────────────────────────
# MITRE ATT&CK tactics y técnicas (subconjunto relevante)
# ──────────────────────────────────────────────────────────

# Mapa: patrones → TTPs
PATTERN_TO_TTP = {
    # Reconocimiento
    "nmap": ("T1046", "Network Service Scanning"),
    "masscan": ("T1046", "Network Service Scanning"),
    "zmap": ("T1046", "Network Service Scanning"),
    "nessus": ("T1046", "Network Service Scanning"),
    "openvas": ("T1046", "Network Service Scanning"),
    "whois": ("T1590", "Gather Victim Network Info"),
    "dnsenum": ("T1590", "Gather Victim Network Info"),
    "dnsrecon": ("T1590", "Gather Victim Network Info"),

    # Initial Access
    "sqli": ("T1190", "Exploit Public-Facing Application"),
    "union select": ("T1190", "Exploit Public-Facing Application"),
    "1=1": ("T1190", "Exploit Public-Facing Application"),
    "sleep(": ("T1190", "Exploit Public-Facing Application"),
    "rfi": ("T1190", "Exploit Public-Facing Application"),
    "lfi": ("T1190", "Exploit Public-Facing Application"),
    "../": ("T1190", "Exploit Public-Facing Application"),
    "..\\": ("T1190", "Exploit Public-Facing Application"),
    "/etc/passwd": ("T1190", "Exploit Public-Facing Application"),
    "c:\\boot": ("T1190", "Exploit Public-Facing Application"),

    # Execution
    "shell": ("T1059", "Command and Scripting Interpreter"),
    "exec": ("T1059", "Command and Scripting Interpreter"),
    "eval": ("T1059", "Command and Scripting Interpreter"),
    "system(": ("T1059", "Command and Scripting Interpreter"),
    "passthru": ("T1059", "Command and Scripting Interpreter"),
    "popen": ("T1059", "Command and Scripting Interpreter"),
    "powershell": ("T1059", "Command and Scripting Interpreter"),
    "cmd.exe": ("T1059", "Command and Scripting Interpreter"),
    "bash": ("T1059", "Command and Scripting Interpreter"),

    # Persistence
    "cron": ("T1053", "Scheduled Task/Job"),
    "schtasks": ("T1053", "Scheduled Task/Job"),
    "at.exe": ("T1053", "Scheduled Task/Job"),
    "service": ("T1543", "Create or Modify System Process"),
    "sc create": ("T1543", "Create or Modify System Process"),
    "startup": ("T1547", "Boot or Logon Autostart Execution"),
    "registry run": ("T1547", "Boot or Logon Autostart Execution"),
    "hkcu\\software\\microsoft\\windows\\currentversion\\run": ("T1547", "Boot or Logon Autostart Execution"),

    # Privilege Escalation
    "sudo": ("T1548", "Abuse Elevation Control Mechanism"),
    "su -": ("T1548", "Abuse Elevation Control Mechanism"),
    "runas": ("T1548", "Abuse Elevation Control Mechanism"),
    "whoami": ("T1033", "System Owner/User Discovery"),
    "id": ("T1033", "System Owner/User Discovery"),

    # Defense Evasion
    "kill": ("T1562", "Impair Defenses"),
    "pkill": ("T1562", "Impair Defenses"),
    "taskkill": ("T1562", "Impair Defenses"),
    "stop-service": ("T1562", "Impair Defenses"),
    "disable": ("T1562", "Impair Defenses"),
    "uninstall": ("T1562", "Impair Defenses"),
    "clear-eventlog": ("T1070", "Indicator Removal"),
    "wevtutil cl": ("T1070", "Indicator Removal"),
    "rm -rf": ("T1070", "Indicator Removal"),
    "del /f": ("T1070", "Indicator Removal"),

    # Credential Access
    "mimikatz": ("T1003", "OS Credential Dumping"),
    "sekurlsa": ("T1003", "OS Credential Dumping"),
    "comsvcs.dll": ("T1003", "OS Credential Dumping"),
    "lsass": ("T1003", "OS Credential Dumping"),
    "procdump": ("T1003", "OS Credential Dumping"),
    "wdigest": ("T1003", "OS Credential Dumping"),
    "sam": ("T1003", "OS Credential Dumping"),
    "system.reg": ("T1003", "OS Credential Dumping"),
    "security.reg": ("T1003", "OS Credential Dumping"),
    "kerberoast": ("T1558", "Steal or Forge Kerberos Tickets"),
    "tgsrep": ("T1558", "Steal or Forge Kerberos Tickets"),
    "asrep": ("T1558", "Steal or Forge Kerberos Tickets"),
    "hashcat": ("T1110", "Brute Force"),
    "john": ("T1110", "Brute Force"),
    "hydra": ("T1110", "Brute Force"),
    "medusa": ("T1110", "Brute Force"),
    "ncrack": ("T1110", "Brute Force"),
    "brute": ("T1110", "Brute Force"),

    # Discovery
    "ipconfig": ("T1016", "System Network Configuration Discovery"),
    "ifconfig": ("T1016", "System Network Configuration Discovery"),
    "netstat": ("T1049", "System Network Connections Discovery"),
    "arp -a": ("T1016", "System Network Configuration Discovery"),
    "route": ("T1016", "System Network Configuration Discovery"),
    "hostname": ("T1082", "System Information Discovery"),
    "uname": ("T1082", "System Information Discovery"),
    "systeminfo": ("T1082", "System Information Discovery"),
    "tasklist": ("T1057", "Process Discovery"),
    "ps aux": ("T1057", "Process Discovery"),
    "ls": ("T1083", "File and Directory Discovery"),
    "dir": ("T1083", "File and Directory Discovery"),
    "findstr": ("T1083", "File and Directory Discovery"),
    "grep": ("T1083", "File and Directory Discovery"),
    "net user": ("T1069", "Permission Groups Discovery"),
    "net group": ("T1069", "Permission Groups Discovery"),
    "net localgroup": ("T1069", "Permission Groups Discovery"),
    "ldap": ("T1482", "Domain Trust Discovery"),
    "adfind": ("T1482", "Domain Trust Discovery"),
    "bloodhound": ("T1482", "Domain Trust Discovery"),
    "sharphound": ("T1482", "Domain Trust Discovery"),

    # Lateral Movement
    "ssh": ("T1021", "Remote Services"),
    "rdp": ("T1021", "Remote Services"),
    "winrm": ("T1021", "Remote Services"),
    "wmic": ("T1021", "Remote Services"),
    "psexec": ("T1021", "Remote Services"),
    "scp": ("T1570", "Lateral Tool Transfer"),
    "wget": ("T1105", "Ingress Tool Transfer"),
    "curl": ("T1105", "Ingress Tool Transfer"),
    "certutil": ("T1105", "Ingress Tool Transfer"),
    "bitsadmin": ("T1105", "Ingress Tool Transfer"),

    # Collection
    "zip": ("T1560", "Archive Collected Data"),
    "tar": ("T1560", "Archive Collected Data"),
    "rar": ("T1560", "Archive Collected Data"),
    "compress": ("T1560", "Archive Collected Data"),
    "screenshot": ("T1113", "Screen Capture"),

    # Command and Control
    "nc": ("T1571", "Non-Standard Port"),
    "ncat": ("T1571", "Non-Standard Port"),
    "ncat.exe": ("T1571", "Non-Standard Port"),
    "connect-back": ("T1071", "Application Layer Protocol"),
    "reverse": ("T1071", "Application Layer Protocol"),
    "dns-tunnel": ("T1572", "Protocol Tunneling"),

    # Exfiltration
    "ftp": ("T1048", "Exfiltration Over Alternative Protocol"),
    "smtp": ("T1048", "Exfiltration Over Alternative Protocol"),
    "mail": ("T1048", "Exfiltration Over Alternative Protocol"),
    "upload": ("T1048", "Exfiltration Over Alternative Protocol"),
    "post": ("T1567", "Exfiltration Over Web Service"),
}

# Grafo de transiciones TTP → TTP (para Intent Predictor)
TTP_TRANSITION_GRAPH = {
    # Scanning → Exploit → Credential Access → Lateral Movement
    "T1046": ["T1190", "T1210", "T1590"],
    "T1190": ["T1003", "T1059", "T1057", "T1083"],
    "T1210": ["T1003", "T1059"],
    "T1003": ["T1558", "T1552", "T1021", "T1078"],
    "T1558": ["T1021", "T1078"],
    "T1552": ["T1021", "T1078"],
    "T1059": ["T1003", "T1546", "T1057", "T1083", "T1562"],
    "T1082": ["T1083", "T1069", "T1482"],
    "T1083": ["T1003", "T1552"],
    "T1069": ["T1482", "T1078"],
    "T1482": ["T1558", "T1078"],
    "T1078": ["T1021", "T1003"],
    "T1021": ["T1003", "T1560", "T1048"],
    "T1562": ["T1562", "T1070"],
    "T1070": ["T1070", "T1560"],
    "T1560": ["T1048", "T1567"],
    "T1048": [],
    "T1567": [],
    "T1110": ["T1078", "T1003"],
    "T1053": ["T1059", "T1543"],
    "T1543": ["T1059"],
    "T1548": ["T1003", "T1069"],
    "T1547": ["T1059", "T1078"],
}

# Factores de peligrosidad por TTP
TTP_DANGER_WEIGHTS = {
    "T1003": 0.9,  # Credential Dumping — crítico
    "T1558": 0.85,  # Kerberoasting — crítico
    "T1078": 0.8,   # Valid Accounts — alto
    "T1021": 0.8,   # Remote Services — alto
    "T1560": 0.7,   # Collection — alto
    "T1048": 0.8,   # Exfiltration — crítico
    "T1567": 0.8,   # Exfiltration over Web — crítico
    "T1190": 0.6,   # Exploit — medio-alto
    "T1110": 0.6,   # Brute Force — medio
    "T1059": 0.5,   # Execution — medio
    "T1562": 0.7,   # Impair Defenses — alto
    "T1070": 0.6,   # Indicator Removal — medio-alto
    "T1046": 0.2,   # Scanning — bajo
    "T1590": 0.1,   # Recon — muy bajo
    "T1053": 0.4,   # Scheduled Task — medio
    "T1543": 0.5,   # Create/Modify Process — medio
}


class TTPClassifier:
    """Clasifica comandos/payloads en TTPs de MITRE ATT&CK usando
    matching de patrones + respaldo del WorldModel ML existente."""

    def __init__(self, use_ml: bool = True):
        self.use_ml = use_ml
        self._wm = None
        self._stats = defaultdict(int)
        
        self.use_bert = TRANSFORMERS_AVAILABLE
        if self.use_bert:
            try:
                self.tokenizer = AutoTokenizer.from_pretrained('sentence-transformers/all-MiniLM-L6-v2')
                self.model = AutoModel.from_pretrained('sentence-transformers/all-MiniLM-L6-v2')
                
                # Precompute TTP embeddings
                self.ttp_texts = []
                self.ttp_ids = []
                self.ttp_names = []
                
                ttp_dict = defaultdict(list)
                for pattern, (tid, tname) in PATTERN_TO_TTP.items():
                    ttp_dict[(tid, tname)].append(pattern)
                
                for (tid, tname), patterns in ttp_dict.items():
                    text = f"{tname} {' '.join(patterns)}"
                    self.ttp_texts.append(text)
                    self.ttp_ids.append(tid)
                    self.ttp_names.append(tname)
                    
                inputs = self.tokenizer(self.ttp_texts, padding=True, truncation=True, return_tensors='pt')
                with torch.no_grad():
                    outputs = self.model(**inputs)
                self.ttp_embeddings = outputs.last_hidden_state.mean(dim=1)
            except Exception as e:
                LOG.error(f"Failed to load BERT model: {e}")
                self.use_bert = False

    def classify(self, command: str, user: str = "", password: str = "") -> dict:
        """Clasifica un comando/payload en una o más TTPs.
        Retorna {ttp_id, name, confidence, all_ttps}"""
        cmd_lower = command.lower()
        matches = []

        if self.use_bert and command:
            try:
                inputs = self.tokenizer([cmd_lower], padding=True, truncation=True, return_tensors='pt')
                with torch.no_grad():
                    outputs = self.model(**inputs)
                cmd_embedding = outputs.last_hidden_state.mean(dim=1)
                
                similarities = F.cosine_similarity(cmd_embedding, self.ttp_embeddings)
                best_idx = similarities.argmax().item()
                best_score = similarities[best_idx].item()
                
                if best_score > 0.3: # Threshold de similitud
                    matches.append({
                        "ttp_id": self.ttp_ids[best_idx],
                        "name": self.ttp_names[best_idx],
                        "confidence": float(best_score),
                        "source": "bert_embedding"
                    })
            except Exception as e:
                LOG.error(f"Error in BERT classification: {e}")

        if not matches:
            # 1. Pattern matching directo (fallback)
            for pattern, (ttp_id, ttp_name) in PATTERN_TO_TTP.items():
                if pattern in cmd_lower:
                    matches.append({"ttp_id": ttp_id, "name": ttp_name,
                                    "confidence": 0.7, "source": "pattern"})

        # 2. Clasificación adicional por credenciales
        if user or password:
            common_users = ["admin", "root", "sa", "administrator", "oracle"]
            if user.lower() in common_users:
                matches.append({"ttp_id": "T1110", "name": "Brute Force",
                                "confidence": 0.5, "source": "credential"})

        # 3. Reforzar con WorldModel ML si está disponible
        if self.use_ml and not matches:
            try:
                from ml.inference import obtener_modelo
                if self._wm is None:
                    self._wm = obtener_modelo()
                if self._wm and self._wm.disponible:
                    # Construir estado mínimo para el modelo
                    estado = self._build_ml_state(cmd_lower)
                    feats = self._wm.extract_features(estado)
                    if feats:
                        pred = self._wm.predecir(feats)
                        tipo_ml = pred.get("pi_tipo", "")
                        if tipo_ml and tipo_ml != "desconocido":
                            # Mapear tipo ML a TTP
                            ml_to_ttp = {
                                "sqli": ("T1190", "Exploit Public-Facing Application"),
                                "xss": ("T1190", "Exploit Public-Facing Application"),
                                "scanner": ("T1046", "Network Service Scanning"),
                                "brute-force": ("T1110", "Brute Force"),
                                "exploit": ("T1190", "Exploit Public-Facing Application"),
                                "cmd_inject": ("T1059", "Command and Scripting Interpreter"),
                                "lfi": ("T1190", "Exploit Public-Facing Application"),
                                "rfi": ("T1190", "Exploit Public-Facing Application"),
                                "fuzzing": ("T1046", "Network Service Scanning"),
                            }
                            if tipo_ml in ml_to_ttp:
                                tid, tname = ml_to_ttp[tipo_ml]
                                matches.append({"ttp_id": tid, "name": tname,
                                                "confidence": 0.4, "source": "ml"})
            except Exception:
                pass

        # 4. Si no hay matches, clasificar como desconocido
        if not matches:
            matches.append({"ttp_id": "T1078.999", "name": "Unknown Behavior",
                            "confidence": 0.1, "source": "unknown"})

        # 5. Consolidar: quitar duplicados, quedarse con el de mayor confianza
        consolidated = {}
        for m in matches:
            tid = m["ttp_id"]
            if tid not in consolidated or m["confidence"] > consolidated[tid]["confidence"]:
                consolidated[tid] = m

        # Estadísticas
        for tid in consolidated:
            self._stats[tid] += 1

        all_ttps = list(consolidated.values())
        best = max(all_ttps, key=lambda x: x["confidence"])

        return {
            "ttp_id": best["ttp_id"],
            "name": best["name"],
            "confidence": round(best["confidence"], 2),
            "all_ttps": [t["ttp_id"] for t in all_ttps],
            "source": best["source"],
        }

    def _build_ml_state(self, cmd: str) -> dict:
        """Construye estado mínimo para el WorldModel ML."""
        hp_features = {"sesiones_hoy": 1, "ataques_detectados": 1,
                       "tipos_distintos": 1, "herramientas_distintas": 1,
                       "tasa_exito_login": 0.5}
        # Patrones de ataque embebidos (evita import circular con honeypot/__init__)
        attack_patterns = [
            ["admin", "root", "1234", "password", "test"],
            ["user", "login", "oracle", "mysql", "sa"],
            ["nmap", "masscan", "zmap", "nessus"],
            ["shell", "exec", "eval", "system(", "popen"],
            ["' or", "1=1", "union select", "sleep("],
            ["<script", "alert(", "onerror="],
            ["AAAA", "BBBB", "admin'", "null", "%00"],
            ["http://", "https://", "ftp://"],
            ["../", "..\\", "etc/passwd", "boot.ini"],
            [";", "|", "`", "$(", "&&"],
        ]
        for i, patterns in enumerate(attack_patterns):
            for p in patterns:
                if p in cmd:
                    hp_features["tipos_distintos"] = max(
                        hp_features["tipos_distintos"], i + 1)
                    break
        return {
            "ia_core": {}, "defense": {}, "blockchain": {},
            "classic_crypto": {}, "honeypot": hp_features,
            "entropy": {}, "cortex": {}, "paz": {}, "memoria": {},
        }

    def stats(self) -> dict:
        return dict(self._stats)


class AttackerProfileMatrix:
    """In-memory profile storage using Python dicts para el perfil del atacante.
    Almacena: tooling, timing, targets, TTPs observadas, sesiones."""

    def __init__(self, max_sessions: int = 1000):
        self._profiles: dict[str, dict] = {}
        self._max_sessions = max_sessions
        self._lock = threading.Lock()

    def get_or_create(self, ip: str) -> dict:
        with self._lock:
            if ip not in self._profiles:
                self._profiles[ip] = self._new_profile(ip)
            return self._profiles[ip]

    def _new_profile(self, ip: str) -> dict:
        return {
            "ip": ip,
            "first_seen": time.time(),
            "last_seen": time.time(),
            "session_count": 0,
            "tooling": set(),
            "ttp_sequence": deque(maxlen=50),
            "ttp_counts": defaultdict(int),
            "ttp_timeline": [],
            "tactics_observed": set(),
            "timing_profile": {
                "avg_pause": 0.0,
                "total_actions": 0,
                "burst_detected": False,
                "nighttime_ops": False,
            },
            "target_preference": {
                "high_value_files": set(),
                "protocols": set(),
                "auth_attempts": [],
            },
            "commands": deque(maxlen=100),
            "sessions": [],
            "danger_score": 0.0,
            "intent_prediction": {},
            "geo": {},
        }

    def update(self, ip: str, command: str = "", ttp: dict = None,
               tool: str = "", port: int = 0, session_data: dict = None):
        """Actualiza el perfil del atacante con nueva observación."""
        profile = self.get_or_create(ip)
        profile["last_seen"] = time.time()
        now = time.time()

        with self._lock:
            # Sesión
            if session_data:
                profile["sessions"].append(session_data)
                profile["session_count"] += 1
                if len(profile["sessions"]) > self._max_sessions:
                    profile["sessions"] = profile["sessions"][-self._max_sessions:]

            # Tooling
            if tool and tool != "desconocida":
                profile["tooling"].add(tool)

            # Comando
            if command:
                profile["commands"].append(command)

                # Detectar archivos de alto valor
                high_value = [".pfx", ".p12", "config.php", "passwords",
                              "credentials", "secret", "token", ".env",
                              "dump", "backup", ".sql", "id_rsa", ".git"]
                for hv in high_value:
                    if hv in command.lower():
                        profile["target_preference"]["high_value_files"].add(hv)

                # Detectar protocolos
                protocols = ["MSSQL", "MySQL", "LDAP", "SMB", "SSH", "RDP",
                             "HTTP", "HTTPS", "PostgreSQL", "Redis", "MongoDB"]
                for p in protocols:
                    if p.lower() in command.lower():
                        profile["target_preference"]["protocols"].add(p)

                # Timing
                prev = profile["timing_profile"]
                prev["total_actions"] += 1
                if profile["ttp_timeline"]:
                    pause = now - profile["ttp_timeline"][-1]["timestamp"]
                    prev["avg_pause"] = (prev["avg_pause"] * (prev["total_actions"] - 1)
                                         + pause) / prev["total_actions"]
                    # Detectar burst (>10 acciones en <30 segundos)
                    recent = [t for t in profile["ttp_timeline"]
                              if now - t["timestamp"] < 30]
                    if len(recent) > 10:
                        prev["burst_detected"] = True
                # Nighttime ops (entre 00:00 y 06:00 hora local)
                hour = __import__("datetime").datetime.now().hour
                if hour < 6:
                    prev["nighttime_ops"] = True

            # TTP
            if ttp:
                tid = ttp.get("ttp_id", "unknown")
                profile["ttp_sequence"].append(tid)
                profile["ttp_counts"][tid] = profile["ttp_counts"].get(tid, 0) + 1
                profile["ttp_timeline"].append({
                    "ttp_id": tid,
                    "timestamp": now,
                    "confidence": ttp.get("confidence", 0.5),
                })
                # Extraer táctica del TTP
                tactic_num = int(tid[1:3]) if len(tid) >= 4 else 0
                tactic_categories = {
                    1: "TA0001", 2: "TA0002", 3: "TA0003", 4: "TA0004",
                    5: "TA0005", 6: "TA0006", 7: "TA0007", 8: "TA0008",
                    9: "TA0009", 10: "TA0010", 11: "TA0011", 12: "TA0012",
                    13: "TA0002", 14: "TA0003", 15: "TA0004",
                }
                tactic = tactic_categories.get(tactic_num // 100, "TA0000")
                profile["tactics_observed"].add(tactic)

            # Auth attempts
            if session_data and "user" in session_data:
                profile["target_preference"]["auth_attempts"].append({
                    "user": session_data["user"],
                    "password": session_data.get("pass", "***"),
                    "timestamp": now,
                })

            # Danger score
            profile["danger_score"] = self._calculate_danger(profile)

    def _calculate_danger(self, profile: dict) -> float:
        """Calcula score de peligrosidad [0, 1] basado en TTPs observadas."""
        if not profile["ttp_counts"]:
            return 0.0

        # Ponderar por peso de cada TTP
        total_weight = 0.0
        max_possible = 0.0

        for tid, count in profile["ttp_counts"].items():
            weight = TTP_DANGER_WEIGHTS.get(tid, 0.3)
            total_weight += weight * min(count, 5) / 5.0
            max_possible += 1.0

        base_score = total_weight / max_possible if max_possible > 0 else 0.0

        # Bonus por comportamiento agresivo
        bonus = 0.0
        if profile["timing_profile"]["nighttime_ops"]:
            bonus += 0.1
        if profile["timing_profile"]["burst_detected"]:
            bonus += 0.1
        if len(profile["tooling"]) >= 3:
            bonus += 0.1

        return min(1.0, base_score + bonus)

    def get_profile(self, ip: str) -> Optional[dict]:
        """Retorna el perfil completo (con sets convertidos a listas)."""
        profile = self._profiles.get(ip)
        if not profile:
            return None
        return self._serialize(profile)

    def _serialize(self, p: dict) -> dict:
        """Convierte sets a listas para serialización JSON."""
        result = {}
        for k, v in p.items():
            if isinstance(v, set):
                result[k] = list(v)
            elif isinstance(v, deque):
                result[k] = list(v)
            elif isinstance(v, defaultdict):
                result[k] = dict(v)
            elif isinstance(v, dict):
                result[k] = self._serialize(v)
            else:
                result[k] = v
        return result

    def list_active(self, min_danger: float = 0.0, max_age: float = 300) -> list[dict]:
        """Lista perfiles activos (vistos en los últimos max_age segundos)."""
        now = time.time()
        active = []
        for ip, profile in self._profiles.items():
            if now - profile["last_seen"] > max_age:
                continue
            if profile["danger_score"] < min_danger:
                continue
            active.append(self._serialize(profile))
        return sorted(active, key=lambda x: x["danger_score"], reverse=True)

    def count_active(self, max_age: float = 300) -> int:
        now = time.time()
        return sum(1 for p in self._profiles.values()
                   if now - p["last_seen"] <= max_age)

    def cleanup(self, max_age: float = 3600):
        """Limpia perfiles antiguos."""
        now = time.time()
        to_delete = [ip for ip, p in self._profiles.items()
                     if now - p["last_seen"] > max_age]
        for ip in to_delete:
            del self._profiles[ip]

    def estado(self) -> dict:
        return {
            "total_profiles": len(self._profiles),
            "active_5min": self.count_active(300),
            "active_1h": self.count_active(3600),
        }


class IntentPredictor:
    """Predice la próxima TTP y el objetivo del atacante usando
    el grafo de transiciones MITRE ATT&CK."""

    def __init__(self):
        self._graph = TTP_TRANSITION_GRAPH

    def predict_next(self, ttp_sequence: list[str]) -> list[dict]:
        """Predice las TTPs más probables como próxima acción.
        Retorna lista ordenada por probabilidad descendente."""
        if not ttp_sequence:
            return [{"ttp_id": "T1046", "name": "Network Service Scanning",
                     "probability": 0.3}]

        current_ttp = ttp_sequence[-1]

        # Posibles transiciones desde la TTP actual
        candidates = self._graph.get(current_ttp, [])
        if not candidates:
            return [{"ttp_id": current_ttp, "name": "Unknown",
                     "probability": 0.5}]

        # Contar frecuencias de TTPs en la secuencia para ajustar pesos
        freq = defaultdict(int)
        for t in ttp_sequence:
            freq[t] += 1

        results = []
        for next_ttp in candidates:
            # Probabilidad base
            prob = 1.0 / len(candidates)

            # Ajustar por frecuencia: si ya hizo esta TTP, menos probable
            if next_ttp in freq:
                prob *= 0.7 ** freq[next_ttp]

            # Ajustar por peligrosidad: TTPs más peligrosas reciben leve bonus
            danger = TTP_DANGER_WEIGHTS.get(next_ttp, 0.3)
            prob *= (1.0 + danger * 0.2)

            name = next((n for p, (t, n) in PATTERN_TO_TTP.items() if t == next_ttp),
                        "Unknown Technique")
            results.append({
                "ttp_id": next_ttp,
                "name": name,
                "probability": round(prob, 3),
            })

        return sorted(results, key=lambda x: x["probability"], reverse=True)

    def predict_intent(self, profile: dict) -> dict:
        """Predice el objetivo general del atacante."""
        ttp_seq = list(profile.get("ttp_sequence", []))
        if not ttp_seq:
            return {"primary_goal": "reconnaissance",
                    "secondary": "unknown", "confidence": 0.1}

        # Mapear TTPs a fases del kill chain
        kill_chain_map = {
            "reconnaissance": {"T1590", "T1046"},
            "weaponization": set(),
            "delivery": {"T1190", "T1210"},
            "exploitation": {"T1190", "T1059", "T1210"},
            "installation": {"T1543", "T1547", "T1053"},
            "command_and_control": {"T1071", "T1571"},
            "actions_on_objectives": {"T1003", "T1558", "T1560", "T1048",
                                      "T1567", "T1110", "T1078", "T1021"},
        }

        # Ver en qué fase está más avanzado
        phases_seen = {}
        for ttp in ttp_seq:
            for phase, ttps in kill_chain_map.items():
                if ttp in ttps:
                    phases_seen[phase] = phases_seen.get(phase, 0) + 1

        if not phases_seen:
            return {"primary_goal": "reconnaissance", "secondary": "unknown",
                    "confidence": 0.1}

        # Últimas TTPs determinan objetivo inmediato
        recent = ttp_seq[-3:] if len(ttp_seq) >= 3 else ttp_seq

        # Mapa: TTPs recientes → objetivo
        intent_map = {
            ("T1003",): ("credential_theft", "Dumping credenciales del sistema"),
            ("T1558",): ("credential_theft", "Kerberoasting / AS-REP roasting"),
            ("T1078",): ("lateral_movement", "Usando credenciales válidas"),
            ("T1021",): ("lateral_movement", "Movimiento lateral vía servicios remotos"),
            ("T1560", "T1048"): ("data_exfiltration", "Recolectando y exfiltrando datos"),
            ("T1560", "T1567"): ("data_exfiltration", "Recolectando y exfiltrando vía web"),
            ("T1110",): ("credential_theft", "Fuerza bruta de credenciales"),
            ("T1543", "T1053"): ("persistence", "Instalando persistencia"),
            ("T1562",): ("defense_evasion", "Deshabilitando defensas"),
            ("T1070",): ("defense_evasion", "Eliminando evidencia"),
            ("T1046",): ("reconnaissance", "Escaneando la red"),
            ("T1190",): ("initial_access", "Explotando aplicación pública"),
        }

        # Buscar el intent que mejor matchee las TTPs recientes
        best_score = 0
        best_intent = ("reconnaissance", "Observando la red")
        for ttp_tuple, intent in intent_map.items():
            match = sum(1 for t in recent if t in ttp_tuple)
            score = match / max(len(ttp_tuple), len(recent))
            if score > best_score:
                best_score = score
                best_intent = intent

        # Determinar fase más avanzada
        max_phase = max(phases_seen, key=phases_seen.get)
        secondary = max_phase

        return {
            "primary_goal": best_intent[0],
            "description": best_intent[1],
            "secondary": secondary,
            "confidence": round(max(0.3, min(0.95, best_score * 1.5)), 2),
        }


class BehavioralProfiler:
    """Orquestador del profiling conductual. Conecta:
    TTPClassifier + AttackerProfileMatrix + IntentPredictor"""

    def __init__(self, use_ml: bool = True):
        self.ttp_classifier = TTPClassifier(use_ml=use_ml)
        self.matrix = AttackerProfileMatrix()
        self.intent_predictor = IntentPredictor()
        self._event_hooks = []
        self.attacker_graphs = {}

    def process_observation(self, ip: str, command: str = "",
                            user: str = "", password: str = "",
                            tool: str = "", port: int = 0,
                            session_data: dict = None) -> dict:
        """Procesa una observación del atacante y actualiza su perfil."""
        # 1. Clasificar comando en TTPs
        ttp = self.ttp_classifier.classify(command, user, password)

        # Build NetworkX graph if available
        if NETWORKX_AVAILABLE:
            if ip not in self.attacker_graphs:
                self.attacker_graphs[ip] = nx.DiGraph()
            
            graph = self.attacker_graphs[ip]
            node_id = f"action_{len(graph.nodes)}"
            action_desc = f"{command} ({ttp.get('ttp_id', 'Unknown')})"
            graph.add_node(node_id, description=action_desc, timestamp=time.time())
            if len(graph.nodes) > 1:
                prev_node_id = f"action_{len(graph.nodes) - 2}"
                graph.add_edge(prev_node_id, node_id)

        # 2. Actualizar perfil en la matriz
        self.matrix.update(ip, command=command, ttp=ttp,
                           tool=tool, port=port, session_data=session_data)

        # 3. Obtener perfil actualizado
        profile = self.matrix.get_profile(ip)

        # 4. Predecir intención
        if profile:
            intent = self.intent_predictor.predict_intent(profile)
            profile["intent_prediction"] = intent

        # 5. Predecir próxima TTP
        if profile and profile.get("ttp_sequence"):
            next_ttps = self.intent_predictor.predict_next(
                profile["ttp_sequence"])
            if profile:
                profile["next_ttp"] = next_ttps
                profile["next_ttp_expected"] = next_ttps[0]["ttp_id"] if next_ttps else ""

        return profile or {}

    def get_profile(self, ip: str) -> Optional[dict]:
        """Retorna el perfil completo del atacante."""
        return self.matrix.get_profile(ip)

    def list_active(self, min_danger: float = 0.0) -> list[dict]:
        return self.matrix.list_active(min_danger=min_danger)

    def count_active(self) -> int:
        return self.matrix.count_active()

    def cleanup(self):
        self.matrix.cleanup()

    def register_hook(self, callback):
        self._event_hooks.append(callback)

    def estado(self) -> dict:
        return {
            "profiles": self.matrix.estado(),
            "ttp_stats": self.ttp_classifier.stats(),
            "active": self.count_active(),
        }
