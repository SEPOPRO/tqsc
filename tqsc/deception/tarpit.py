"""
tqsc/deception/tarpit.py — Trampa TCP multi-protocolo con delays.
"""
import logging, socket, threading, time, secrets
from typing import Optional

LOG = logging.getLogger("tqsc.deception.tarpit")


class Tarpit:
    """Ralentiza atacantes con respuestas TCP lentas en multiples puertos."""

    def __init__(self):
        self._conexiones = 0
        self._activo = False
        self._pool = threading.BoundedSemaphore(100)

    def _handler(self, conn, perfil: str):
        with self._pool:
            try:
                conn.settimeout(30)
                data = conn.recv(1024)
                if not data:
                    return
                if perfil == "ssh":
                    conn.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")
                    time.sleep(3)
                for delay in [1, 2, 4, 8]:
                    try:
                        conn.sendall(secrets.token_bytes(64))
                        time.sleep(delay)
                    except (socket.timeout, BrokenPipeError, ConnectionResetError):
                        return
            except (socket.timeout, OSError):
                pass
            finally:
                conn.close()

    def _servir(self, puerto: int, perfil: str = "generic"):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", puerto))
            s.listen(10)
            s.settimeout(1)
            while self._activo:
                try:
                    conn, addr = s.accept()
                    self._conexiones += 1
                    LOG.info("🐢 Tarpit: %s en puerto %d", addr[0], puerto)
                    threading.Thread(target=self._handler, args=(conn, perfil), daemon=True).start()
                except socket.timeout:
                    continue
        except OSError:
            pass
        finally:
            s.close()

    def iniciar(self):
        if self._activo:
            return
        self._activo = True
        puertos = {2322: "ssh", 2323: "http", 2324: "generic", 2325: "generic", 8081: "generic"}
        for puerto, perfil in puertos.items():
            threading.Thread(target=self._servir, args=(puerto, perfil), daemon=True, name=f"Tarpit-{puerto}").start()
        LOG.info("🐢 Tarpit activo: %d puertos", len(puertos))

    def detener(self):
        self._activo = False

    def estado(self) -> dict:
        return {"conexiones": self._conexiones}
