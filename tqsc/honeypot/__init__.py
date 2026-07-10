"""
TQSC v1.0 — Honeypots Cognitivos"""
import socket, threading, json, hashlib, logging, os, time, secrets, struct
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from random import choice, uniform, randint

from utils.secure_storage import write as _write

LOG = logging.getLogger("tqsc.honeypot")
TQSC_TEST = os.environ.get("TQSC_TEST_MODE") == "1"

try:
    from utils.event_bus import evento as _evento
except Exception:
    _evento = None

PUERTOS_SEÑUELO = [22, 80, 443, 3306, 8080, 8443, 21, 25, 1433, 5432, 6379, 27017]

USUARIOS_FALSOS = {
    "root":       {"shell": "/bin/bash", "home": "/root", "uid": 0, "level": "admin"},
    "admin":      {"shell": "/bin/bash", "home": "/home/admin", "uid": 1000, "level": "sudo"},
    "www-data":   {"shell": "/usr/sbin/nologin", "home": "/var/www", "uid": 33, "level": "user"},
    "deploy":     {"shell": "/bin/bash", "home": "/home/deploy", "uid": 1001, "level": "sudo"},
    "postgres":   {"shell": "/bin/bash", "home": "/var/lib/postgresql", "uid": 102, "level": "user"},
    "mysql":      {"shell": "/usr/sbin/nologin", "home": "/var/lib/mysql", "uid": 103, "level": "user"},
    "backup":     {"shell": "/bin/bash", "home": "/home/backup", "uid": 1002, "level": "sudo"},
}


class HoneypotSession:
    TOOL_FINGERPRINTS = {
        "nmap":       ["nmap", "masscan", "zmap"],
        "metasploit": ["msf", "exploit", "payload"],
        "sqlmap":     ["sqlmap", "sql", "dump"],
        "hydra":      ["hydra", "medusa", "ncrack"],
        "burp":       ["burp", "intruder", "repeater"],
        "custom":     [],
    }

    def __init__(self, ip: str, puerto: int, user_agent: str = ""):
        self.ip = ip; self.puerto = puerto
        self.timestamp = datetime.now().isoformat()
        self.comandos: list[dict] = []
        self.credenciales: dict = {}
        self.tipo_ataque: str = "desconocido"
        self.herramienta: str = "desconocida"
        self.duracion: float = 0.0
        self._inicio = time.time()
        self._ua = user_agent

    def detectar_herramienta(self, payload: str) -> str:
        p = payload.lower()
        for tool, señales in self.TOOL_FINGERPRINTS.items():
            if any(s in p for s in señales):
                return tool
        return "custom"

    def cerrar(self):
        self.duracion = round(time.time() - self._inicio, 1)
        self.comandos.append({"t": "SESSION_END", "data": f"duracion={self.duracion}s"})

    def to_dict(self) -> dict:
        return {"ip": self.ip, "puerto": self.puerto, "timestamp": self.timestamp,
                "duracion_s": self.duracion, "herramienta": self.herramienta,
                "tipo_ataque": self.tipo_ataque, "comandos": self.comandos,
                "credenciales": self.credenciales,
                "hash": hashlib.sha256(f"{self.ip}{self.timestamp}".encode()).hexdigest()[:16]}


class PatternInverter:
    TIPOS_ATAQUE = {
        "brute-force": ["admin", "root", "1234", "password", "test", "pass"],
        "dictionary":  ["user", "login", "oracle", "mysql", "cisco", "sa"],
        "scanner":     ["nmap", "masscan", "zmap", "nessus", "openvas"],
        "exploit":     ["shell", "exec", "eval", "system(", "passthru", "popen"],
        "sqli":        ["' or", "1=1", "union select", "sleep(", "order by"],
        "xss":         ["<script", "alert(", "onerror=", "onload=", "javascript:"],
        "fuzzing":     ["AAAA", "BBBB", "admin'", "null", "undefined", "%00"],
        "rfi":         ["http://", "https://", "ftp://", "include(", "require("],
        "lfi":         ["../", "..\\", "etc/passwd", "etc/shadow", "c:\\boot",
                       "/etc/passwd", "/etc/shadow", "/etc/hosts", "/proc/",
                       "boot.ini", "win.ini"],
        "cmd_inject":  [";", "|", "`", "$(", "&&", "||"],
    }

    def __init__(self):
        self.sesiones: dict[str, dict] = {}
        self.logger = logging.getLogger("tqsc.honeypot.pattern")

    def clasificar(self, user: str = "", pwd: str = "", comando: str = "",
                   ip: str = "") -> dict:
        user_l = user.lower(); pwd_l = pwd.lower(); cmd_l = comando.lower()
        senales: dict[str, float] = {}
        for tipo, patrones in self.TIPOS_ATAQUE.items():
            for p in patrones:
                if p in user_l: senales[tipo] = max(senales.get(tipo, 0), 0.3)
                if p in pwd_l: senales[tipo] = max(senales.get(tipo, 0), 0.5)
                if p in cmd_l: senales[tipo] = max(senales.get(tipo, 0), 0.8)
        # World Model enhancement
        self._reforzar_con_ml(cmd_l, senales)
        if not senales:
            return {"tipo": "desconocido", "confianza": 0.1, "accion": "monitorear"}
        mejor_tipo = max(senales, key=senales.get)
        confianza = senales[mejor_tipo]
        if confianza >= 0.7: accion = "bloquear"
        elif confianza >= 0.4: accion = "engañar"
        else: accion = "monitorear"
        # Emitir evento real al HUD
        if mejor_tipo != "desconocido" and _evento:
            _evento("ataque", "PatternInverter", mejor_tipo,
                   f"conf={confianza:.2f}",
                   "crit" if confianza >= 0.7 else "warn",
                   accion)
        return {"tipo": mejor_tipo, "confianza": round(confianza, 2), "accion": accion, "detalles": list(senales.keys())}

    def _reforzar_con_ml(self, comando: str, senales: dict):
        try:
            from ml.inference import obtener_modelo
            wm = obtener_modelo()
            if not wm.disponible: return
            estado = {
                "ia_core": {}, "defense": {}, "blockchain": {}, "classic_crypto": {},
                "honeypot": {"sesiones_hoy": 1, "ataques_detectados": 1,
                            "tipos_distintos": 1, "herramientas_distintas": 1,
                            "tasa_exito_login": 0.5},
                "entropy": {}, "cortex": {}, "paz": {}, "memoria": {},
            }
            # Codificar el comando actual en el estado
            for tipo in self.TIPOS_ATAQUE:
                if any(p in comando for p in self.TIPOS_ATAQUE[tipo]):
                    estado["honeypot"]["tipos_distintos"] = max(
                        estado["honeypot"]["tipos_distintos"],
                        list(self.TIPOS_ATAQUE.keys()).index(tipo) + 1)
            feats = wm.extract_features(estado)
            if not feats: return
            pred = wm.predecir(feats)
            tipo_ml = pred.get("pi_tipo", "")
            conf_ml = pred.get("pi_severidad_num", 0.35)
            if tipo_ml and tipo_ml != "desconocido":
                senales[tipo_ml] = max(senales.get(tipo_ml, 0), min(conf_ml * 0.08, 0.6))
        except Exception:
            pass

    def retardo_realista(self, comando: str) -> float:
        base = uniform(0.05, 0.15)
        if len(comando) > 50: base += 0.1
        if any(x in comando for x in ["grep", "find", "ps"]): base += uniform(0.1, 0.3)
        return base

    def recordar_sesion(self, ip: str, datos: dict):
        if ip not in self.sesiones:
            self.sesiones[ip] = {"comandos": [], "clasificacion": None}
        self.sesiones[ip]["comandos"].append(datos)
        if len(self.sesiones[ip]["comandos"]) > 20:
            self.sesiones[ip]["comandos"].pop(0)

    def reporte_sesion(self, ip: str) -> dict:
        sesion = self.sesiones.get(ip, {}); comandos = sesion.get("comandos", [])
        if not comandos: return {"ip": ip, "ataques": 0}
        tipos = {}
        for c in comandos:
            t = c.get("tipo", "desconocido")
            tipos[t] = tipos.get(t, 0) + 1
        return {"ip": ip, "ataques": len(comandos), "tipos": tipos}


class ResponseShaper:
    def __init__(self, ip: str = ""):
        self.ip = ip
        self._modo = choice(["Linux", "Ubuntu", "Debian"])
        self._hostname = choice(["web01", "db01", "app01", "prod-web", "backup-srv"])
        self._timestamp_base = datetime.now() - timedelta(days=randint(30, 365))
        self._credenciales_ok = False
        self._usuario_actual = USUARIOS_FALSOS["www-data"]

    def banner(self) -> bytes:
        banners = {"Linux": b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n",
                   "Ubuntu": b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n",
                   "Debian": b"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1\r\n"}
        return banners.get(self._modo, banners["Linux"])

    def prompt(self) -> bytes:
        return f"{self._usuario_actual['level']}@{self._hostname}:{self._usuario_actual['home']}$ ".encode()

    def login(self, user: str, pwd: str) -> tuple[bool, bytes]:
        user = user.strip().lower()
        if user in USUARIOS_FALSOS:
            time.sleep(uniform(0.5, 1.5))
            self._usuario_actual = USUARIOS_FALSOS[user]
            self._credenciales_ok = True
            return True, b"Last login: " + self._timestamp_base.strftime('%a %b %d %H:%M:%S %Y').encode() + b" from 10.0.0.1\n"
        time.sleep(uniform(0.2, 0.5))
        return False, b"User not found.\n"

    def responder(self, comando: str) -> bytes:
        cmd = comando.strip().lower()
        time.sleep(uniform(0.03, 0.12))
        respuestas = {
            "whoami":     f"{self._usuario_actual['level']}\n".encode(),
            "id":         f"uid={self._usuario_actual['uid']}({self._usuario_actual['level']}) gid=100(users) groups=100(users)\n".encode(),
            "pwd":        f"{self._usuario_actual['home']}\n".encode(),
            "hostname":   f"{self._hostname}\n".encode(),
            "uname -a":   f"Linux {self._hostname} 5.15.0-generic #1 SMP x86_64 GNU/Linux\n".encode(),
            "uname -r":   b"5.15.0-generic\n", "date": f"{datetime.now().strftime('%a %b %d %H:%M:%S %Z %Y')}\n".encode(),
            "uptime":     f" {randint(1,99)}:{randint(0,59)} up {randint(1,365)} days, load: {uniform(0.1,2.0):.2f}\n".encode(),
            "free -m":    f"Mem: 7985 {randint(1000,4000)} {randint(500,2000)}\nSwap: 2047 0 2047\n".encode(),
            "df -h":      "/dev/sda1 197G 45G 152G 23% /\n".encode(),
            "ifconfig":   f"eth0: inet 10.0.0.{randint(2,254)} netmask 255.255.255.0\n".encode(),
            "env":        f"SHELL=/bin/bash\nUSER={self._usuario_actual['level']}\nHOME={self._usuario_actual['home']}\nPATH=/usr/local/sbin:/usr/bin\n".encode(),
        }
        if "cat /etc/passwd" in cmd or "cat /etc/shadow" in cmd:
            return b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        for archivo in ["/etc/hostname", "/etc/hosts", "/etc/os-release"]:
            if f"cat {archivo}" in cmd:
                return f"{self._hostname}\n".encode()
        return respuestas.get(cmd, choice([b"bash: command not found\n", b"bash: permission denied\n",
                                          b"Segmentation fault (core dumped)\n", b"Bus error\n"]))


class BehaviorCollector:
    def __init__(self, puerto: int = 2222, data_dir: str = "data",
                 max_conexiones: int = 100, rate_limit: int = 3):
        self.puerto = puerto; self.data_dir = Path(data_dir)
        self.sesiones: list[HoneypotSession] = []
        self._activo = False; self._conteo_ip: dict[str, list[float]] = {}
        self._puertos_extra: list[int] = []; self._max_conexiones = max_conexiones
        self._rate_limit = rate_limit; self._pattern = PatternInverter()

    def _check_rate_limit(self, ip: str) -> bool:
        ahora = time.time()
        self._conteo_ip[ip] = [t for t in self._conteo_ip.get(ip, []) if ahora - t < 60]
        if len(self._conteo_ip.get(ip, [])) >= self._rate_limit:
            LOG.warning("Rate limit: %s (%d/min)", ip, len(self._conteo_ip[ip]))
            return False
        self._conteo_ip.setdefault(ip, []).append(ahora)
        return True

    def iniciar(self):
        self._activo = True
        hilo = threading.Thread(target=self._escuchar, daemon=True)
        hilo.start()
        for puerto in PUERTOS_SEÑUELO[:5]:
            h = threading.Thread(target=self._escuchar_puerto, args=(puerto,), daemon=True)
            h.start(); self._puertos_extra.append(puerto)
        LOG.info("Honeypot: %d puertos señuelo activos (%d principal)", len(self._puertos_extra)+1, self.puerto)
        return hilo

    def _escuchar(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.settimeout(3)
        try: s.bind(("0.0.0.0", self.puerto)); s.listen(self._max_conexiones)
        except OSError: return
        while self._activo:
            try:
                conn, addr = s.accept()
                ip = addr[0]
                if not self._check_rate_limit(ip):
                    conn.close(); continue
                threading.Thread(target=self._manejar, args=(conn, addr, self.puerto), daemon=True).start()
            except socket.timeout: continue
            except Exception: continue

    def _escuchar_puerto(self, puerto: int):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.settimeout(5)
        try: s.bind(("0.0.0.0", puerto)); s.listen(10)
        except OSError: return
        while self._activo:
            try:
                conn, addr = s.accept()
                time.sleep(uniform(5, 15))
                conn.close()
            except: continue

    def _manejar(self, conn: socket.socket, addr: tuple, puerto: int):
        sesion = HoneypotSession(addr[0], puerto)
        shaper = ResponseShaper(addr[0])
        try:
            conn.sendall(shaper.banner())
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            time.sleep(uniform(0.1, 0.3))
            conn.sendall(b"login: ")
            user_data = conn.recv(4096).strip().decode(errors="ignore")
            sesion.herramienta = sesion.detectar_herramienta(user_data)
            conn.sendall(b"Password: ")
            pwd_data = conn.recv(4096).strip().decode(errors="ignore")
            sesion.credenciales = {"user": user_data, "pass": pwd_data}
            # Clasificar con ML + reglas
            clasif = self._pattern.clasificar(user=user_data, pwd=pwd_data)
            sesion.tipo_ataque = clasif["tipo"]
            ok, msg = shaper.login(user_data, pwd_data)
            if not ok:
                conn.sendall(msg); time.sleep(uniform(0.5, 1.0))
                conn.sendall(b"login: "); conn.close(); return
            conn.sendall(msg); conn.sendall(shaper.prompt())
            while self._activo:
                conn.settimeout(60)
                try: data = conn.recv(4096)
                except socket.timeout: break
                if not data: break
                cmd = data.strip().decode(errors="ignore")
                sesion.comandos.append({"t": "cmd", "data": cmd})
                clasif = self._pattern.clasificar(comando=cmd)
                sesion.tipo_ataque = clasif["tipo"] if clasif["tipo"] != "desconocido" else sesion.tipo_ataque
                time.sleep(self._pattern.retardo_realista(cmd))
                conn.sendall(shaper.responder(cmd) + shaper.prompt())
        except (socket.timeout, ConnectionError, OSError, ValueError) as e:
            LOG.debug("Honeypot %s: %s", addr[0], e)
        finally:
            sesion.cerrar(); conn.close()
            self._persistir(sesion); self.sesiones.append(sesion)

    def _persistir(self, sesion: HoneypotSession):
        _write(self.data_dir / f"honeypot_{sesion.ip.replace('.','_')}.json", sesion.to_dict())

    def detener(self):
        self._activo = False
        LOG.info("Honeypot detenido (%d sesiones capturadas)", len(self.sesiones))
