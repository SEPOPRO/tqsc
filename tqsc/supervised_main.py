"""
TQSC v2.0 — Modo Supervisado (multi-proceso)
Cada núcleo como proceso independiente con watchdog.
Uso: python run.py --supervised
"""
import logging, os, sys, time, hashlib

LOG = logging.getLogger("tqsc.supervised")

# Núcleos que pueden ejecutarse como procesos independientes
# (nombre, módulo, clase, args_posicionales)
NUCLEOS = [
    ("blockchain",     "blockchain.fork_sealant", "ForkSealant",        ["data"]),
    ("entropia",       "utils.entropy_engine",    "EntropyNoiseEngine", ["data"]),
    ("defensa_fisica", "defense",                 "DefenseCore",        []),
    ("cuantico",       "classic_crypto",          "ClassicCryptoCore",  ["data"]),
    ("honeypot",       "honeypot",                "BehaviorCollector",  ["data"]),
    ("ia_core",        "core.octarcq",            "OctaRCQX8",          []),
    ("cortex",         "core.cortex",             "CortexDeConfinamiento", [5, 3, "data"]),
    ("memoria",        "core.memoria_episodica",  "MemoriaEpisodica",   ["data"]),
]

# Núcleos que requieren wrapper especial
NUCLEOS_ESPECIALES = {
    "paz": """
import sys, os
sys.path.insert(0, r"{BASE}")
from core.protocolo_paz import IdentidadAgente, ProtocoloPaz
from utils.nucleus_daemon import NucleusDaemon
daemon = NucleusDaemon("paz", {PORT})
agente = IdentidadAgente("TQSC_Supervised")
nucleo = ProtocoloPaz(agente)
daemon.iniciar(nucleo)
daemon.loop()
""",
}


def main_supervisado():
    from supervisor import Supervisor

    sup = Supervisor(max_reinicios=3)
    for nombre, modulo, clase, args in NUCLEOS:
        sup.registrar(nombre, modulo, clase, args)

    # Registrar núcleos especiales
    for nombre, script_template in NUCLEOS_ESPECIALES.items():
        puerto = 19100 + int(hashlib.sha256(nombre.encode()).hexdigest(), 16) % 1000
        script = script_template.format(BASE=os.path.dirname(__file__).replace("\\", "\\\\"), PORT=puerto)
        sup._registrar_especial(nombre, script, puerto)

    sup.iniciar()
    LOG.info("Supervisor: %d núcleos en procesos independientes", len(NUCLEOS))

    try:
        while True:
            time.sleep(10)
            est = sup.estado()
            activos = sum(1 for v in est.values() if v["activo"])
            LOG.info("Supervisor: %d/%d núcleos activos", activos, len(NUCLEOS))
            if activos == 0:
                LOG.critical("Supervisor: 0 núcleos activos — algo grave ocurrió")
                break
    except KeyboardInterrupt:
        sup.detener()
        LOG.info("Supervisor: detenido")


if __name__ == "__main__":
    main_supervisado()
