"""TQSC v1.0 — Honeypots Cognitivos"""
import socket, threading, json, hashlib, logging, os, time, secrets, struct
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from random import choice, uniform, randint

from utils.secure_storage import write as _write

LOG = logging.getLogger("tqsc.honeypot")
TQSC_TEST = os.environ.get("TQSC_TEST_MODE") == "1"

# ── Puertos señuelo (además del principal) ──
PUERTOS_SEÑUELO = [22, 80, 443, 3306, 8080, 8443, 21, 25, 1433, 5432, 6379, 27017]

# ── USUARIOS Y CONTRASEÑAS FALSAS ──
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
    """Registro completo con fingerprinting de herramienta y GeoIP simulado."""
    TOOL_FINGERPRINTS = {
        "nmap":       ["nmap", "masscan", "zmap"],
        "metasploit": ["msf", "exploit", "payload"],
        "sqlmap":     ["sqlmap", "sql", "dump"],
        "hydra":      ["hydra", "medusa", "ncrack"],
        "burp":       ["burp", "intruder", "repeater"],
        "custom":     [],  # catch-all
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
        return {
            "ip": self.ip, "puerto": self.puerto,
            "timestamp": self.timestamp, "duracion_s": self.duracion,
            "herramienta": self.herramienta, "tipo_ataque": self.tipo_ataque,
            "comandos": self.comandos, "credenciales": self.credenciales,
            "hash": hashlib.sha256(f"{self.ip}{self.timestamp}".encode()).hexdigest()[:16],
        }


class PatternInverter:
    """Clasifica ataques con scoring difuso + simulación de delays reales."""

    TIPOS_ATAQUE = {
        "brute-force": ["admin", "root", "1234", "password", "test", "pass"],
        "dictionary":  ["user", "login", "oracle", "mysql", "cisco", "oracle", "sa"],
        "scanner":     ["nmap", "masscan", "zmap", "nessus", "openvas"],
        "exploit":     ["shell", "exec", "eval", "system(", "passthru", "popen"],
        "sqli":        ["' or", "1=1", "union select", "sleep(", "order by"],
        "xss":         ["<script", "alert(", "onerror=", "onload=", "javascript:"],
        "fuzzing":     ["AAAA", "BBBB", "admin'", "null", "undefined", "%00"],
        "rfi":         ["http://", "https://", "ftp://", "include(", "require("],
        "lfi":         ["../", "..\\", "etc/passwd", "etc/shadow", "c:\\boot"],
        "cmd_inject":  [";", "|", "`", "$(", "&&", "||"],
    }

    def __init__(self):
        self.sesiones: dict[str, dict] = {}
        self.logger = logging.getLogger("tqsc.honeypot.pattern")

    def clasificar(self, user: str = "", pwd: str = "",
                   comando: str = "", ip: str = "") -> dict:
        user_l = user.lower(); pwd_l = pwd.lower(); cmd_l = comando.lower()
        senales: dict[str, float] = {}
        for tipo, patrones in self.TIPOS_ATAQUE.items():
            for p in patrones:
                if p in user_l: senales[tipo] = max(senales.get(tipo, 0), 0.3)
                if p in pwd_l: senales[tipo] = max(senales.get(tipo, 0), 0.5)
                if p in cmd_l: senales[tipo] = max(senales.get(tipo, 0), 0.8)
        if not senales:
            return {"tipo": "desconocido", "confianza": 0.1, "accion": "monitorear"}
        mejor_tipo = max(senales, key=senales.get)
        confianza = senales[mejor_tipo]
        if confianza >= 0.7: accion = "bloquear"
        elif confianza >= 0.4: accion = "engañar"
        else: accion = "monitorear"
        return {"tipo": mejor_tipo, "confianza": round(confianza, 2),
                "accion": accion, "detalles": list(senales.keys())}

    def retardo_realista(self, comando: str) -> float:
        """Simula latencia de procesamiento real."""
        base = uniform(0.01, 0.05)
        if len(comando) > 50: base += 0.1
        if "grep" in comando or "find" in comando or "ps " in comando:
            base += uniform(0.05, 0.3)
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
    """Simula un sistema LINUX COMPLETO con ~50 comandos y archivos consistentes."""

    def __init__(self, ip: str = ""):
        self.ip = ip
        self._modo = choice(["Linux", "Ubuntu", "Debian"])
        self._hostname = choice(["web01", "db01", "app01", "prod-web", "backup-srv"])
        self._timestamp_base = datetime.now() - timedelta(days=randint(30, 365))
        self._credenciales_ok = False
        self._usuario_actual = USUARIOS_FALSOS["www-data"]
        self._archivos: dict[str, str] = self._generar_archivos()

    def _generar_archivos(self) -> dict[str, str]:
        base_ts = int(self._timestamp_base.timestamp())
        return {
            "/etc/hostname": f"{self._hostname}\n",
            "/etc/hosts": "127.0.0.1 localhost\n10.0.0.10  web01.internal\n10.0.0.20  db01.internal\n",
            "/etc/os-release": f'NAME="Ubuntu"\nVERSION="22.04 LTS"\nID=ubuntu\n',
            "/proc/uptime": f"{randint(100000, 5000000)} {randint(50000, 2500000)}\n",
            "/etc/ssh/sshd_config": "Port 22\nPermitRootLogin prohibit-password\nPasswordAuthentication yes\n",
            "/home/admin/.bash_history": "ls\ncd /var/www\ncat wp-config.php\nsudo systemctl restart apache2\n",
            "/var/log/auth.log": self._generar_authlog(base_ts),
        }

    def _generar_authlog(self, base_ts: int) -> str:
        lines = []
        for i in range(20):
            ts = datetime.fromtimestamp(base_ts - i * 3600)
            ips = [f"192.168.1.{randint(2,254)}", f"10.0.0.{randint(2,254)}"]
            lines.append(f"{ts.strftime('%b %d %H:%M:%S')} sshd[{randint(1000,9999)}]: Failed password for {choice(['root','admin','www-data'])} from {choice(ips)} port {randint(10000,60000)} ssh2\n")
        return "".join(lines)

    def banner(self) -> bytes:
        banners = {
            "Linux":  b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n",
            "Ubuntu": b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n",
            "Debian": b"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1\r\n",
        }
        return banners.get(self._modo, banners["Linux"])

    def prompt(self) -> bytes:
        return f"{self._usuario_actual['level']}@{self._hostname}:{self._usuario_actual['home']}$ ".encode()

    def login(self, user: str, pwd: str) -> tuple[bool, bytes]:
        """Simula login real con delay progresivo."""
        user = user.strip().lower()
        if user in USUARIOS_FALSOS:
            time.sleep(uniform(0.5, 1.5))  # delay de autenticación realista
            if user == "root" and pwd.strip() == "":
                return False, b"Password: "
            if pwd.strip() in ("admin123", "password", "1234", "root", user):
                self._usuario_actual = USUARIOS_FALSOS[user]
                self._credenciales_ok = True
                return True, b"Last login: " + self._timestamp_base.strftime('%a %b %d %H:%M:%S %Y').encode() + b" from 10.0.0.1\n"
            return False, b"Permission denied, please try again.\n"
        time.sleep(uniform(0.2, 0.5))
        return False, b"User not found.\n"

    def responder(self, comando: str) -> bytes:
        cmd = comando.strip().lower()
        time.sleep(uniform(0.01, 0.08))  # latencia realista

        respuestas = {
            "whoami":     f"{self._usuario_actual['level']}\n".encode(),
            "id":         f"uid={self._usuario_actual['uid']}({self._usuario_actual['level']}) gid=100(users) groups=100(users)\n".encode(),
            "pwd":        f"{self._usuario_actual['home']}\n".encode(),
            "hostname":   f"{self._hostname}\n".encode(),
            "uname -a":   f"Linux {self._hostname} 5.15.0-generic #1 SMP x86_64 GNU/Linux\n".encode(),
            "uname -r":   b"5.15.0-generic\n",
            "date":       f"{datetime.now().strftime('%a %b %d %H:%M:%S %Z %Y')}\n".encode(),
            "uptime":     f" {randint(1, 99)}:{randint(0,59)} up {randint(1, 365)} days,  {randint(0,23)}:{randint(0,59)},  1 user,  load average: {uniform(0.1, 2.0):.2f}, {uniform(0.1, 1.5):.2f}, {uniform(0.1, 1.0):.2f}\n".encode(),
            "free -m":    f"              total        used        free      shared  buff/cache   available\nMem:           7985         {randint(1000,4000)}        {randint(500,2000)}         123        {randint(1000,3000)}        {randint(2000,5000)}\nSwap:          2047           0        2047\n".encode(),
            "df -h":      "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1       197G  45G  152G  23% /\ntmpfs           3.9G  0%   3.9G   0% /dev/shm\n".encode(),
            "ls -la":     f"total {randint(20,100)}\ndrwxr-xr-x  {self._usuario_actual['level']} {self._usuario_actual['level']}  4096 {self._timestamp_base.strftime('%b %d %Y')} .\ndrwxr-xr-x  root root  4096 {self._timestamp_base.strftime('%b %d %Y')} ..\n-rw-r--r--  {self._usuario_actual['level']} {self._usuario_actual['level']}   220 {self._timestamp_base.strftime('%b %d %Y')} .bash_logout\n-rw-r--r--  {self._usuario_actual['level']} {self._usuario_actual['level']}  3771 {self._timestamp_base.strftime('%b %d %Y')} .bashrc\n-rw-r--r--  {self._usuario_actual['level']} {self._usuario_actual['level']}   807 {self._timestamp_base.strftime('%b %d %Y')} .profile\n".encode(),
            "ls":         f"Desktop  Documents  Downloads  Music  Pictures  Public  Templates  Videos\n".encode() if self._usuario_actual['uid'] != 0 else "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var\n".encode(),
            "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:1002:1002:Backup:/home/backup:/bin/bash\n".encode(),
            "cat /etc/shadow": "root:$6$xyz$hash...:19000:0:99999:7:::\nwww-data:*:19001:0:99999:7:::\n".encode(),
            "ps aux":     f"USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1 {randint(100000,200000)} {randint(2000,5000)} ?        Ss   {self._timestamp_base.strftime('%b%d')}   0:01 /sbin/init\n{self._usuario_actual['level']}  {randint(1000,9999)}  0.0  0.2 {randint(50000,150000)} {randint(3000,8000)} ?        S    {self._timestamp_base.strftime('%b%d')}   0:00 sshd: {self._usuario_actual['level']}@pts/0\n".encode(),
            "netstat -tlnp": "Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    \ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      {}/sshd          \ntcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      {}/mysqld        \ntcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      {}/apache2        \n".format(randint(1000,9999), randint(1000,9999), randint(1000,9999)).encode(),
            "ifconfig":   f"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.0.{randint(2,254)}  netmask 255.255.255.0  broadcast 10.0.0.255\n        inet6 fe80::{secrets.token_hex(4)}  prefixlen 64  scopeid 0x20<link>\n        ether 02:42:ac:{randint(10,20):02x}:{randint(10,20):02x}:{randint(10,20):02x}  txqueuelen 0  (Ethernet)\n".encode(),
            "env":        f"SHELL=/bin/bash\nUSER={self._usuario_actual['level']}\nPWD={self._usuario_actual['home']}\nHOME={self._usuario_actual['home']}\nLANG=en_US.UTF-8\nTERM=xterm-256color\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n".encode(),
            "history":    f"  {randint(1,5)}  ls\n  {randint(5,10)}  cd /var/www\n  {randint(10,15)}  cat wp-config.php\n".encode(),
            "sudo -l":    f"Matching Defaults entries for {self._usuario_actual['level']} on {self._hostname}\n    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n\nUser {self._usuario_actual['level']} may run the following commands on {self._hostname}:\n    (ALL : ALL) ALL\n".encode() if self._usuario_actual['uid'] == 0 else f"User {self._usuario_actual['level']} is not in the sudoers file.  This incident will be reported.\n".encode(),
            "wget":       b"--2024-01-15 10:30:00--  http://example.com/file\nResolving example.com (example.com)... 93.184.216.34\nConnecting to example.com (example.com)|93.184.216.34|:80... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: 102400 (100K)\nSaving to: 'file'\n\n100%[======================================>] 102,400    500KB/s\n\n2024-01-15 10:30:01 (500 KB/s) - 'file' saved\n",
            "curl":       b"<html>\n<head><title>Example Page</title></head>\n<body>\n<h1>Hello from internal server</h1>\n<p>This is a test page.</p>\n</body>\n</html>\n",
            "find / -perm -4000": "/usr/bin/su\n/usr/bin/sudo\n/usr/bin/passwd\n/usr/sbin/pppd\n".encode(),
            "systemctl status apache2": f"● apache2.service - The Apache HTTP Server\n   Loaded: loaded (/lib/systemd/system/apache2.service; enabled; vendor preset: enabled)\n   Active: active (running) since {self._timestamp_base.strftime('%a %Y-%m-%d %H:%M:%S')} UTC; {randint(30,365)} days ago\n Main PID: {randint(1000,9999)} (apache2)\n    Tasks: 11 (limit: 4687)\n   Memory: {randint(10,100)}.0M\n".encode(),
        }

        for archivo, contenido in self._archivos.items():
            if cmd.startswith(f"cat {archivo}") or cmd.startswith(f"cat {archivo.split('/')[-1]}"):
                return contenido.encode()

        respuestas.setdefault("", self.prompt())
        return respuestas.get(cmd, choice([
            b"bash: command not found\n",
            b"bash: permission denied\n",
            b"bash: No such file or directory\n",
            b"Segmentation fault (core dumped)\n",
            b"Bus error\n",
        ]))


class BehaviorCollector:
    """Señuelo multi-puerto con engaño progresivo y delays realistas."""

    def __init__(self, puerto: int = 2222, data_dir: str = "data",
                 max_conexiones: int = 100, rate_limit: int = 3):
        self.puerto = puerto
        self.data_dir = Path(data_dir)
        self.sesiones: list[HoneypotSession] = []
        self._activo = False
        self._conteo_ip: dict[str, int] = {}
        self._puertos_extra: list[int] = []
        self._max_conexiones = max_conexiones
        self._rate_limit = rate_limit
        self._pattern = PatternInverter()

    def iniciar(self):
        self._activo = True
        hilo = threading.Thread(target=self._escuchar, daemon=True)
        hilo.start()
        for puerto in PUERTOS_SEÑUELO[:5]:
            h = threading.Thread(target=self._escuchar_puerto, args=(puerto,), daemon=True)
            h.start()
            self._puertos_extra.append(puerto)
        LOG.info("Honeypot: %d puertos señuelo activos (%d principal)", len(self._puertos_extra)+1, self.puerto)
        return hilo

    def _escuchar(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(3)
        try:
            s.bind(("0.0.0.0", self.puerto))
            s.listen(self._max_conexiones)
        except OSError:
            return
        while self._activo:
            try:
                conn, addr = s.accept()
                threading.Thread(target=self._manejar, args=(conn, addr, self.puerto), daemon=True).start()
            except socket.timeout: continue
            except Exception: continue

    def _escuchar_puerto(self, puerto: int):
        """Puerto señuelo que solo acepta conexión y registra, sin interactuar."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(5)
        try:
            s.bind(("0.0.0.0", puerto))
            s.listen(10)
        except OSError:
            return
        while self._activo:
            try:
                conn, addr = s.accept()
                # Puerto señuelo: delay y cierre
                time.sleep(uniform(5, 15))
                conn.close()
                self._conteo_ip[addr[0]] = self._conteo_ip.get(addr[0], 0) + 1
            except: continue

    def _check_rate_limit(self, ip: str) -> bool:
        """Rate limit por IP en ventana de 60s."""
        ahora = int(time.time())
        self._conteo_ip = {k: v for k, v in self._conteo_ip.items() if ahora - v < 60}
        count = self._conteo_ip.get(ip, 0)
        if count >= self._rate_limit:
            LOG.warning("Rate limit: %s (%d conexiones)", ip, count)
            return False
        self._conteo_ip[ip] = self._conteo_ip.get(ip, 0) + 1
        return True

    def _manejar(self, conn: socket.socket, addr: tuple, puerto: int):
        sesion = HoneypotSession(addr[0], puerto)
        shaper = ResponseShaper(addr[0])
        try:
            # Banner
            conn.sendall(shaper.banner())
            time.sleep(uniform(0.1, 0.3))
            conn.sendall(b"login: ")
            user_data = conn.recv(4096).strip().decode(errors="ignore")
            sesion.herramienta = sesion.detectar_herramienta(user_data)
            conn.sendall(b"Password: ")
            pwd_data = conn.recv(4096).strip().decode(errors="ignore")
            sesion.credenciales = {"user": user_data, "pass": pwd_data}
            sesion.tipo_ataque = self._pattern.clasificar(user_data, pwd_data)["tipo"]
            # Login simulado
            ok, msg = shaper.login(user_data, pwd_data)
            if not ok:
                conn.sendall(msg)
                time.sleep(uniform(0.5, 1.0))
                conn.sendall(b"login: ")
                conn.close()
                return
            conn.sendall(msg)
            conn.sendall(shaper.prompt())
            while self._activo:
                conn.settimeout(60)
                try:
                    data = conn.recv(4096)
                except socket.timeout:
                    conn.sendall(b"\nConnection to {self._hostname} closed.\n".encode() if hasattr(shaper, '_hostname') else b"\nTimeout.\n")
                    break
                if not data: break
                cmd = data.strip().decode(errors="ignore")
                sesion.comandos.append({"t": "cmd", "data": cmd})
                # Simular latencia realista
                time.sleep(self._pattern.retardo_realista(cmd))
                respuesta = shaper.responder(cmd)
                conn.sendall(respuesta)
                conn.sendall(shaper.prompt())
        except (socket.timeout, ConnectionError, OSError, ValueError) as e:
            LOG.debug("Honeypot %s: %s", addr[0], e)
        finally:
            sesion.cerrar()
            conn.close()
            self._persistir(sesion)
            self.sesiones.append(sesion)

    def _persistir(self, sesion: HoneypotSession):
        _write(self.data_dir / f"honeypot_{sesion.ip.replace('.','_')}.json", sesion.to_dict())

    def detener(self):
        self._activo = False
        LOG.info("Honeypot detenido (%d sesiones capturadas)", len(self.sesiones))
