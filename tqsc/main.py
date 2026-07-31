"""
TQSC v1.0 — Orquestador Principal
Arranque y coordinación de todos los núcleos del sistema (incluye módulos 2031).
"""
import os
import time
import threading
import logging
import hashlib
from pathlib import Path

TQSC_TEST = lambda: os.environ.get("TQSC_TEST_MODE") == "1"

import sys as _sys
_sys.path.insert(0, os.path.dirname(__file__))
from config import DATA_DIR

from blockchain.fork_sealant import ForkSealant, CrossChainTracker
from utils.entropy_engine import EntropyNoiseEngine
from defense import DefenseCore
from classic_crypto import ClassicCryptoCore
from honeypot import BehaviorCollector
from core.octarcq import OctaCore
from core.cortex import CortexDeConfinamiento
from core.protocolo_paz import IdentidadAgente, ProtocoloPaz
from core.memoria_episodica import MemoriaEpisodica
from utils.boot_integrity import verificar, regenerar


class TQSC:
    """BlockDefender Titan Quantum Shield Core — Sistema completo."""

    def __init__(self):
        self.logger = self._setup_logger()
        self.nucleos_activos: dict[str, bool] = {}

        # Núcleo 1: Blockchain / Integridad Distribuida
        self.fork_sealant = ForkSealant(data_dir=str(DATA_DIR))
        self.cross_chain = CrossChainTracker(sealant=self.fork_sealant)

        # Núcleo 2: Entropía / Antifragilidad
        self.entropy = EntropyNoiseEngine(data_dir=str(DATA_DIR))

        # Núcleo 3: Protección Física
        self.defense = DefenseCore()

        # Núcleo 4: Validación Cuántica
        self.quantum = ClassicCryptoCore(data_dir=str(DATA_DIR))

        # Núcleo 5: Honeypots Cognitivos
        self.honeypot = BehaviorCollector(data_dir=str(DATA_DIR))
        # Malla de Engaño (expansión del Núcleo 5) — ARQUITECTURA PROFESIONAL
        try:
            from deception import DeceptionController, SQLiteStorage, AlertEngine
            self._deception_storage = SQLiteStorage()
            self._deception_alerts = AlertEngine(self._deception_storage)
            self.deception = DeceptionController(self._deception_storage, self._deception_alerts)
            self.logger.info("🕸️ Deception Controller cargado (DI + SQLite + MITRE)")
        except Exception as e:
            self.logger.warning("Deception Controller no disponible: %s", e)

        # Núcleo 6: IA Autoevolutiva OctaRCQ-X8
        self.ia_core = OctaCore(data_dir=str(DATA_DIR))

        # 🆕 Módulo 7: Cortex de Confinamiento (supervisor anti-auto-envenenamiento)
        self.cortex = CortexDeConfinamiento(data_dir=str(DATA_DIR))

        # 🆕 Módulo 8: Protocolo de Paz entre Agentes
        agente_tqsc = IdentidadAgente("TQSC_Main")
        self.protocolo_paz = ProtocoloPaz(agente_tqsc)

        # 🆕 Módulo 9: Memoria Episódica con Marca de Agua
        self.memoria = MemoriaEpisodica(data_dir=str(DATA_DIR))

        self.logger.info("🧠 TQSC v1.0 inicializado — 9 núcleos/módulos listos")
        # Doctor TQSC: auto-diagnóstico y reparación
        self.doctor = None

    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger("tqsc")
        logger.setLevel(logging.INFO)
        ch = logging.StreamHandler()
        ch.setFormatter(logging.Formatter("🧊 %(message)s"))
        logger.addHandler(ch)
        # En Docker los logs van solo a stdout
        if not os.environ.get("TQSC_DOCKER"):
            fh = logging.FileHandler(DATA_DIR / "tqsc.log")
            fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
            logger.addHandler(fh)
        return logger

    def iniciar(self):
        self.logger.info("🚀 TQSC arrancando...")

        # Boot integrity check (skip en Docker — imagen inmutable)
        if not TQSC_TEST() and not os.environ.get("TQSC_DOCKER"):
            ok, modificados = verificar()
            if not ok:
                self.logger.critical("🔴 BOOT INTEGRITY FALLÓ — %d archivos comprometidos", len(modificados))
                for m in modificados:
                    self.logger.critical("  ⛔ %s", m)
                raise SystemExit("Boot integrity check failed")

        nucleos = [
            ("blockchain", self._iniciar_blockchain),
            ("entropia", self._iniciar_entropia),
            ("defensa_fisica", self._iniciar_defensa),
            ("cuantico", self._iniciar_cuantico),
            ("honeypot", self._iniciar_honeypot),
            ("ia_core", self._iniciar_ia_core),
            ("cortex", self._iniciar_cortex),
            ("protocolo_paz", self._iniciar_protocolo_paz),
            ("memoria", self._iniciar_memoria),
        ]

        for nombre, fn in nucleos:
            try:
                fn()
                self.nucleos_activos[nombre] = True
                self.logger.info(f"🟢 [{nombre}] activo")
            except Exception as e:
                self.nucleos_activos[nombre] = False
                self.logger.error(f"🔴 [{nombre}] falló: {e}", exc_info=True)

        self.logger.info(f"✅ TQSC listo. {sum(self.nucleos_activos.values())}/{len(nucleos)} núcleos activos.")

        # Doctor TQSC: vigilancia + auto-reparación
        try:
            from utils.doctor import DoctorTQSC
            self.doctor = DoctorTQSC(intervalo=15)
            self.doctor.diagnosticar_tqsc(self)
            self.doctor.iniciar()
            self.logger.info("🩺 Doctor TQSC activo (9 núcleos vigilados)")
        except Exception as e:
            self.logger.warning("Doctor TQSC no disponible: %s", e)

        # SIEM Core: correlación + time-series + ingesta
        try:
            from utils.siem_core import obtener_siem_core
            self.siem = obtener_siem_core()
            self.logger.info("📊 SIEM Core activo (%d reglas de correlación)",
                             len(self.siem._reglas))
        except Exception as e:
            self.logger.warning("SIEM Core no disponible: %s", e)

        # EDR: Filesystem Monitor
        try:
            from utils.fs_monitor import FSMonitor
            self.fs_monitor = FSMonitor(intervalo=30)
            self.fs_monitor.iniciar()
            self.logger.info("📁 EDR Filesystem Monitor activo")
        except Exception as e:
            self.logger.warning("FSMonitor no disponible: %s", e)

        # EDR: Process Analyzer
        try:
            from utils.proc_analyzer import ProcAnalyzer
            self.proc_analyzer = ProcAnalyzer()
            self.logger.info("🧬 EDR Process Analyzer activo")
        except Exception as e:
            self.logger.warning("ProcAnalyzer no disponible: %s", e)

        # EDR: Registry Monitor (Windows)
        try:
            from utils.registry_monitor import RegistryMonitor
            self.reg_monitor = RegistryMonitor(intervalo=60)
            self.reg_monitor.iniciar()
            self.logger.info("🪟 EDR Registry Monitor activo")
        except Exception as e:
            self.logger.warning("RegistryMonitor no disponible: %s", e)

        # EDR: Sysmon (kernel driver ring-0)
        try:
            from utils.sysmon_edr import SysmonReader
            self.sysmon = SysmonReader(intervalo=15)
            self.sysmon.iniciar()
            if self.sysmon.estado()["sysmon_instalado"]:
                self.logger.info("🔄 Sysmon EDR activo (ring-0 vía kernel driver firmado)")
            else:
                self.logger.info("🔄 Sysmon EDR: driver no instalado (opcional)")
        except Exception as e:
            self.logger.warning("Sysmon EDR no disponible: %s", e)

        # Red: PacketWatch + IDS + Firewall
        try:
            from utils.packet_watch import PacketWatch
            self.packet_watch = PacketWatch(intervalo=15)
            self.packet_watch.iniciar()
            self.logger.info("🌐 PacketWatch activo (conexiones + DNS + port scan)")
        except Exception as e:
            self.logger.warning("PacketWatch no disponible: %s", e)

        try:
            from utils.ids import IDSEngine
            self.ids_engine = IDSEngine()
            self.logger.info("🛡️ IDS Engine activo (%d firmas)", 5)
        except Exception as e:
            self.logger.warning("IDS no disponible: %s", e)

        try:
            from utils.firewall import FirewallManager
            self.firewall = FirewallManager()
            self.logger.info("🔒 Firewall Manager activo")
        except Exception as e:
            self.logger.warning("Firewall no disponible: %s", e)

        # Vuln Management: CVE + CIS + dependencias
        try:
            from utils import vuln_mgmt
            self.vuln_mgr = vuln_mgmt.VulnManager()
            self.logger.info("🔍 Vuln Manager activo (%d CVE, %d CIS checks)",
                             len(vuln_mgmt.CVE_DB), len(vuln_mgmt.CIS_CHECKS))
        except Exception as e:
            self.logger.warning("VulnManager no disponible: %s", e)

        return self

    def _iniciar_blockchain(self):
        # STARTUP SELF-TEST: Verify blockchain state with a known test hash during startup
        self.fork_sealant.verificar("abc123")

    def _iniciar_entropia(self):
        resultado = self.entropy.ejecutar_ciclo()
        self.logger.info(f"Entropía: {resultado['entropia']}")

    def _iniciar_defensa(self):
        self.defense.iniciar()
        resultado = self.defense.escanear()
        if resultado["cpu_altos"]:
            self.logger.warning(f"CPU altos: {resultado['cpu_altos']}")
        if resultado.get("syscall_estado", {}).get("anomalias_detectadas"):
            self.logger.warning("SyscallMonitor: anomalías detectadas")

    def _iniciar_cuantico(self):
        # STARTUP SELF-TEST: Synthetic event for quantum module initialization
        evento = {"timestamp": time.time(), "origen": "test", "tipo": "consulta", "hash": hashlib.sha256(b"tqsc_startup").hexdigest()[:16]}
        resultado = self.quantum.procesar(evento)
        self.logger.info(f"Quantum: {resultado}")

    def _iniciar_honeypot(self):
        self.honeypot.iniciar()
        if hasattr(self, "deception"):
            try:
                health = self.deception.iniciar()
                ok = sum(1 for v in health["componentes"].values() if v == "ok")
                self.logger.info("🕸️ Deception: %d/%d componentes activos", ok, len(health["componentes"]))
            except Exception as e:
                self.logger.warning("Deception falló al iniciar: %s", e)
        self.logger.info("Honeypot escuchando en puerto 2222")

    def _iniciar_ia_core(self):
        self.ia_core.recibir_evento("test: inicialización del sistema")
        self.ia_core.rotar()
        estado = self.ia_core.estado()
        self.logger.info(f"IA Core: {len(estado['octantes'])} octantes activos")

    def _iniciar_cortex(self):
        """Verifica que el Cortex arranca y monitorea un ciclo normal."""
        r = self.cortex.registrar_ciclo({
            "n_hipotesis": 5, "confianza_promedio": 0.9,
            "n_fuentes": 3, "errores": 0,
        })
        self.logger.info(f"Cortex: estado={r}")

    def _iniciar_protocolo_paz(self):
        """Registra al agente TQSC como confiable."""
        self.logger.info(f"ProtocoloPaz: agente {self.protocolo_paz.local.nombre} listo")
        self.logger.info(f"  Agentes conocidos: {self.protocolo_paz.registro.agentes}")

    def _iniciar_memoria(self):
        """Almacena un recuerdo de inicialización."""
        r = self.memoria.almacenar("TQSC iniciado correctamente", "sistema")
        estado = self.memoria.verificar_todos()
        self.logger.info(f"Memoria: {estado['total']} recuerdos, {estado['validos']} válidos")

    def detener(self):
        self.logger.info("⏹️ TQSC deteniéndose...")
        self.honeypot.detener()
        if hasattr(self, "deception"):
            self.deception.detener()
        # Detener EDR + SIEM + Doctor
        for mod, name in [(getattr(self, "fs_monitor", None), "FSMonitor"),
                          (getattr(self, "reg_monitor", None), "RegistryMonitor"),
                          (getattr(self, "packet_watch", None), "PacketWatch"),
                          (getattr(self, "sysmon", None), "Sysmon"),
                          (getattr(self, "doctor", None), "Doctor"),
                          (getattr(self, "siem", None), "SIEM")]:
            if mod and hasattr(mod, "detener"):
                try: mod.detener()
                except: pass
        self.nucleos_activos.clear()

    def estado(self) -> dict:
        return {
            "nucleos_activos": self.nucleos_activos,
            "version": "1.0",
            "honeypot_sesiones": len(self.honeypot.sesiones),
            "cortex": self.cortex.estado() if hasattr(self, "cortex") else {},
            "memoria_recuerdos": len(self.memoria.recuerdos) if hasattr(self, "memoria") else 0,
            "protocolo_agentes": len(self.protocolo_paz.registro.agentes) if hasattr(self, "protocolo_paz") else 0,
        }


if __name__ == "__main__":
    sistema = TQSC()
    sistema.iniciar()
    print(sistema.estado())
    sistema.detener()
