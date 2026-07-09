"""
TQSC v1.0 — IA Autoevolutiva
"""
import logging, json, hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional
from core.octa_nucleo import OctaNucleo
from utils.secure_storage import write as _write

logger = logging.getLogger("tqsc.ia")


class ContextWeaver:
    """Fusiona un patrón con su contexto de origen y metadatos de confianza."""

    @staticmethod
    def fusionar(patron: str, entorno: dict = None) -> dict:
        ahora = datetime.now().isoformat()
        return {
            "patron": patron,
            "origen": entorno.get("origen", "desconocido") if entorno else "desconocido",
            "timestamp": ahora,
            "confianza_origen": entorno.get("confianza", 0.5) if entorno else 0.5,
            "tipo_evento": entorno.get("tipo", "general") if entorno else "general",
            "huella": hashlib.md5(f"{patron}{ahora}".encode()).hexdigest()[:12],
        }


class PredictiveReinforcer:
    """Refuerza patrones por frecuencia e importancia."""

    def __init__(self):
        self.frecuencias: dict[str, int] = {}

    def reforzar(self, nucleo: OctaNucleo):
        if not nucleo.buffer: return
        for pat in nucleo.buffer:
            self.frecuencias[pat] = self.frecuencias.get(pat, 0) + 1
        mas_comun = max(nucleo.buffer, key=lambda p: self.frecuencias.get(p, 0))
        nucleo._mutar(f"refuerzo [{self.frecuencias.get(mas_comun, 0)}x]: {mas_comun[:60]}")


class ModelTrainer:
    """Entrena modelos predictivos sobre patrones."""

    def __init__(self):
        self.patrones_vistos: dict[str, int] = {}

    def entrenar(self, nucleo: OctaNucleo):
        if not nucleo.buffer: return
        for pat in nucleo.buffer:
            self.patrones_vistos[pat] = self.patrones_vistos.get(pat, 0) + 1
        nucleo._mutar(f"modelo: {len(self.patrones_vistos)} patrones únicos vistos")


class MutationLogger:
    """Registro completo de mutaciones con exportación."""

    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.log: list[dict] = []

    def registrar(self, nucleo_nombre: str, accion: str, detalle: str):
        entrada = {"timestamp": datetime.now().isoformat(),
                    "nucleo": nucleo_nombre, "accion": accion, "detalle": detalle[:200]}
        self.log.append(entrada)
        if len(self.log) > 1000: self.log = self.log[-500:]

    def exportar(self, ruta: str = "") -> str:
        ruta = ruta or str(self.data_dir / "mutaciones.json")
        _write(Path(ruta), self.log[-100:])
        return ruta

    def logear(self) -> list[dict]:
        return self.log[-20:]
    def tasa_anomalia(self) -> float:
        if len(self.log) < 10: return 0.0
        recientes = self.log[-20:]
        mutaciones = sum(1 for r in recientes if "muta" in r["accion"].lower())
        return mutaciones / max(1, len(recientes))

    def estado(self) -> dict:
        return {"total": len(self.log), "tasa_anomalia": round(self.tasa_anomalia(), 3)}


class CognitiveLoopDetector:
    """Detecta ciclos degenerativos con ventana 5 y umbral 3+ variantes."""
    def __init__(self, nucleo: OctaNucleo = None):
        self.nucleo = nucleo
    def evaluar(self, nucleo: OctaNucleo = None) -> bool:
        n = nucleo or self.nucleo
        if not n: return False
        if len(n.historial) < 3: return False
        recientes = [h.get("patron", "") if isinstance(h, dict) else h
                     for h in n.historial[-8:]]
        if len(set(recientes)) <= 3:
            n.aislar()
            return True
        return False
    detectar = evaluar


class PatternTransfuser:
    """Transfiere patrones entre núcleos con validación anti-envenenamiento."""
    PATRONES_MALICIOSOS = ["rm -rf", "fork bomb", "shutdown", "delete_system"]
    @staticmethod
    def transferir(origen: OctaNucleo, destino: OctaNucleo) -> bool:
        if not origen.buffer: return False
        if origen.estado == "aislado":
            logger.warning("PatternTransfuser: %s aislado, transf. bloqueada", origen.nombre)
            return False
        for pat in origen.buffer[:3]:
            if any(m in pat.lower() for m in PatternTransfuser.PATRONES_MALICIOSOS):
                logger.warning("PatternTransfuser: patrón malicioso bloqueado: %.40s", pat)
                continue
            destino.recibir(pat)
        return True


class ShadowCloneManager:
    """Gestiona clones shadow para failover inmediato (idempotente)."""
    @staticmethod
    def clonar(nucleo: OctaNucleo):
        if not nucleo.shadow:
            nucleo.clonar_shadow()
    @staticmethod
    def restaurar_si_corrupto(principal: OctaNucleo) -> bool:
        if principal.estado == "aislado" and principal.shadow:
            principal.shadow.estado = "activo"
            logger.warning("Shadow activado para %s", principal.nombre)
            return True
        return False


class IAJudicialInterna:
    """Módulo moral y legal. Toda acción destructiva pasa por aquí."""
    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.reglas = {
            "destructivas": [("delete_system", 10, "destrucción del sistema"),
                             ("shutdown_all", 9, "apagado general no autorizado"),
                             ("format_disk", 10, "formateo de disco"),
                             ("rm -rf /", 10, "borrado recursivo de raíz")],
            "privilegios":  [("escalate_privilege", 8, "escalada de privilegios"),
                             ("sudo", 5, "ejecución con sudo"),
                             ("chmod 777", 4, "permisos excesivos")],
            "red":          [("port_scan", 3, "escaneo de puertos"),
                             ("ddos", 7, "ataque de denegación"),
                             ("dns_tunnel", 6, "túnel DNS")],
            "datos":        [("exfiltrate", 8, "exfiltración de datos"),
                             ("encrypt_all", 9, "cifrado masivo (ransomware)"),
                             ("drop database", 9, "borrado de base de datos")],
        }
        self.historial = []
        self.logger = logging.getLogger("tqsc.ia_judicial")

    def juzgar(self, accion: str, contexto: Optional[dict] = None) -> bool:
        a = accion.lower(); puntaje = 0; razones = []
        for cat, reglas in self.reglas.items():
            for patron, sev, razon in reglas:
                if patron in a:
                    puntaje = max(puntaje, sev)
                    razones.append(f"[{cat}] {razon} (sev {sev})")
        aceptable = puntaje < 5
        if not aceptable:
            self.logger.warning("⛔ BLOQUEADA: %.80s | %s", accion, "; ".join(razones))
        entrada = {"timestamp": datetime.now().isoformat(), "accion": accion[:200],
                   "aceptable": aceptable, "puntaje": puntaje, "razones": razones, "contexto": contexto or {}}
        self.historial.append(entrada)
        return aceptable

    def agregar_regla(self, cat: str, patron: str, sev: int, razon: str):
        self.reglas.setdefault(cat, []).append((patron, sev, razon))
    def auditoria(self, n: int = 100) -> list: return self.historial[-n:]
    def exportar(self, ruta=None):
        ruta = Path(ruta) if ruta else self.data_dir / "auditoria_judicial.json"
        _write(ruta, self.historial)
        return str(ruta)
    exportar_auditoria = exportar

    def estado(self) -> dict:
        return {"reglas": sum(len(v) for v in self.reglas.values()), "categorias": list(self.reglas.keys()),
                "decisiones_totales": len(self.historial),
                "bloqueadas": sum(1 for h in self.historial if not h["aceptable"])}


class EthicalConsensusGate:
    """Requiere consenso ponderado entre múltiples decisiones."""
    def __init__(self):
        self.logger = logging.getLogger("tqsc.ethical_gate")
    def decidir(self, decisiones: list[tuple[bool, float]]) -> bool:
        if not decisiones: return False
        peso_f = sum(p for v, p in decisiones if v)
        peso_t = sum(p for _, p in decisiones)
        return peso_f / peso_t > 0.5 if peso_t else False
    @staticmethod
    def decidir_simple(decisiones: list[bool]) -> bool:
        if not decisiones: return False
        return sum(decisiones) >= max(2, len(decisiones) * 2 // 3)


class MetaCoreAdjuster:
    """Escudo neural que aísla núcleos con comportamiento degenerativo."""
    def __init__(self, nucleo: OctaNucleo = None):
        self.nucleo = nucleo
    def evaluar(self, nucleo: OctaNucleo = None):
        n = nucleo or self.nucleo
        if not n: return
        if len(set(n.historial[-10:])) <= 2 and len(n.historial) > 5:
            n.aislar()
            logger.warning(f"{n.nombre} aislado por RCQ-NeuralShield")
    ajustar = evaluar

RCQNeuralShield = MetaCoreAdjuster
