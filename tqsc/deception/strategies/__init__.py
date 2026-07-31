"""
tqsc/deception/strategies/__init__.py — Strategy pattern para SO.
"""
import os, logging

LOG = logging.getLogger("tqsc.deception.strategies")

_ES_WINDOWS = os.name == "nt"


class BaseStrategy:
    @staticmethod
    def crear_usuario(nombre: str, password: str) -> bool:
        raise NotImplementedError

    @staticmethod
    def eliminar_usuario(nombre: str):
        raise NotImplementedError

    @staticmethod
    def auditar_logins(usuarios: list[str]) -> list[str]:
        raise NotImplementedError


class WindowsStrategy(BaseStrategy):
    @staticmethod
    def crear_usuario(nombre: str, password: str) -> bool:
        import subprocess
        r = subprocess.run(["net", "user", nombre, password, "/add", "/passwordchg:no", "/active:yes"],
                          capture_output=True, timeout=10)
        if r.returncode == 0:
            subprocess.run(["net", "localgroup", "Users", nombre, "/add"],
                          capture_output=True, timeout=5)
            return True
        return False

    @staticmethod
    def eliminar_usuario(nombre: str):
        import subprocess
        subprocess.run(["net", "user", nombre, "/delete"], capture_output=True, timeout=5)

    @staticmethod
    def auditar_logins(usuarios: list[str]) -> list[str]:
        import subprocess
        alertas = []
        r = subprocess.run(["wevtutil", "qe", "Security", "/q:",
                           "*[System[(EventID=4624 or EventID=4625)]]",
                           "/c:20", "/e:Security"],
                          capture_output=True, text=True, timeout=10, errors="replace")
        if r.returncode == 0:
            for u in usuarios:
                if u.lower() in r.stdout.lower():
                    alertas.append(f"HoneyCred login detectado: {u}")
        return alertas


class LinuxStrategy(BaseStrategy):
    @staticmethod
    def crear_usuario(nombre: str, password: str) -> bool:
        import subprocess
        try:
            import crypt
            enc = crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512))
        except (ImportError, AttributeError):
            import hashlib
            enc = hashlib.sha256(password.encode()).hexdigest()
        r = subprocess.run(["useradd", "-m", "-s", "/usr/sbin/nologin", "-p", enc, nombre],
                          capture_output=True, timeout=10)
        return r.returncode == 0

    @staticmethod
    def eliminar_usuario(nombre: str):
        import subprocess
        subprocess.run(["userdel", "-r", nombre], capture_output=True, timeout=5)

    @staticmethod
    def auditar_logins(usuarios: list[str]) -> list[str]:
        import subprocess
        alertas = []
        r = subprocess.run(["lastb"], capture_output=True, text=True, timeout=10, errors="replace")
        if r.returncode == 0:
            for u in usuarios:
                if u in r.stdout:
                    alertas.append(f"HoneyCred login detectado: {u} (Linux)")
        return alertas


def get_strategy() -> BaseStrategy:
    if _ES_WINDOWS:
        return WindowsStrategy()
    return LinuxStrategy()
