"""TQSC v2.0 — Supervisor Watchdog (proceso independiente + rate limit)."""
import os, sys, time, json, signal, subprocess, threading, logging
from datetime import datetime
from pathlib import Path
from typing import Optional
from collections import defaultdict

LOG = logging.getLogger("tqsc.supervisor")

SUPERVISOR_PORT = 19100
HEARTBEAT_INTERVAL = 5
HEARTBEAT_TIMEOUT = 15


class NucleoProceso:
    def __init__(self, nombre: str, modulo: str, clase: str, args: list = None, puerto: int = 0):
        self.nombre = nombre; self.modulo = modulo; self.clase = clase
        self.args = args or []; self.puerto = puerto or SUPERVISOR_PORT + hash(nombre) % 1000
        self.proceso: Optional[subprocess.Popen] = None
        self.ultimo_heartbeat: Optional[float] = None
        self.reinicios = 0; self.activo = False

    @property
    def script(self) -> str:
        if hasattr(self, '_script_custom') and self._script_custom:
            return self._script_custom
        args_str = json.dumps(self.args)
        base_dir = os.path.dirname(__file__).replace("\\", "\\\\")
        return f"""
import sys, os, time, json, socket
os.environ.setdefault("TQSC_NUCLEO", "{self.nombre}")
sys.path.insert(0, "{base_dir}")
from {self.modulo} import {self.clase}
from utils.nucleus_daemon import NucleusDaemon
daemon = NucleusDaemon("{self.nombre}", {self.puerto})
try:
    nucleo = {self.clase}(*{args_str})
    daemon.iniciar(nucleo)
    daemon.loop()
except Exception as e:
    print(f"NUCLEO_CRASH:%s" % e, flush=True)
    raise
"""

    def iniciar(self) -> bool:
        try:
            self.proceso = subprocess.Popen([sys.executable, "-c", self.script],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            self.activo = True; self.ultimo_heartbeat = time.time()
            LOG.info("Supervisor: %s iniciado (PID %d, puerto %d)", self.nombre, self.proceso.pid, self.puerto)
            threading.Thread(target=self._leer_stdout, daemon=True).start()
            return True
        except Exception as e:
            LOG.error("Supervisor: error iniciando %s: %s", self.nombre, e)
            return False

    def _leer_stdout(self):
        try:
            for line in self.proceso.stdout:
                line = line.strip()
                if "NUCLEO_CRASH" in line:
                    LOG.critical("Supervisor: %s CRASH: %s", self.nombre, line); self.activo = False
                elif "HEARTBEAT" in line:
                    self.ultimo_heartbeat = time.time()
        except Exception:
            self.activo = False

    def verificar(self) -> bool:
        if not self.activo: return False
        if self.proceso and self.proceso.poll() is not None:
            self.activo = False
            LOG.warning("Supervisor: %s terminó (código %d)", self.nombre, self.proceso.returncode)
            return False
        if self.ultimo_heartbeat and time.time() - self.ultimo_heartbeat > HEARTBEAT_TIMEOUT:
            LOG.warning("Supervisor: %s sin heartbeat (%ds)", self.nombre, time.time() - self.ultimo_heartbeat)
            self.activo = False; return False
        return True

    def detener(self):
        if self.proceso:
            self.proceso.terminate()
            try: self.proceso.wait(timeout=5)
            except subprocess.TimeoutExpired: self.proceso.kill()
            self.activo = False; LOG.info("Supervisor: %s detenido", self.nombre)


class Supervisor:
    def __init__(self, max_reinicios: int = 3):
        self.nucleos: dict[str, NucleoProceso] = {}
        self._activo = False
        self._max_reinicios = max_reinicios
        self._reinicios_por_hora: dict[str, list[float]] = defaultdict(list)
        self._hilo: Optional[threading.Thread] = None

    def _puede_reiniciar(self, nombre: str) -> bool:
        ahora = time.time()
        self._reinicios_por_hora[nombre] = [t for t in self._reinicios_por_hora[nombre] if ahora - t < 3600]
        return len(self._reinicios_por_hora[nombre]) < self._max_reinicios

    def registrar(self, nombre: str, modulo: str, clase: str, args: list = None):
        self.nucleos[nombre] = NucleoProceso(nombre, modulo, clase, args)

    def _registrar_especial(self, nombre: str, script: str, puerto: int):
        """Registra un núcleo con script personalizado."""
        np = NucleoProceso(nombre, "", "", [])
        np.puerto = puerto
        np._script_custom = script
        self.nucleos[nombre] = np

    def iniciar(self):
        self._activo = True
        for n, p in self.nucleos.items(): p.iniciar()
        self._hilo = threading.Thread(target=self._loop, daemon=True)
        self._hilo.start()
        LOG.info("Supervisor: watchdog activo (%d núcleos)", len(self.nucleos))

    def _loop(self):
        while self._activo:
            for nombre, nucleo in list(self.nucleos.items()):
                if not nucleo.verificar():
                    if self._puede_reiniciar(nombre):
                        self._reinicios_por_hora[nombre].append(time.time())
                        LOG.warning("Supervisor: reiniciando %s (intento %d/h)", nombre, len(self._reinicios_por_hora[nombre]))
                        nucleo.iniciar()
                    else:
                        LOG.critical("Supervisor: %s EXCEDIÓ LÍMITE DE REINICIOS/h", nombre)
            time.sleep(HEARTBEAT_INTERVAL)

    def estado(self) -> dict:
        return {n: {"activo": p.activo, "reinicios_hora": len(self._reinicios_por_hora.get(n, [])),
                    "pid": p.proceso.pid if p.proceso and p.proceso.poll() is None else None}
                for n, p in self.nucleos.items()}

    def detener(self):
        self._activo = False
        for n in self.nucleos.values(): n.detener()
        LOG.info("Supervisor: detenido")
