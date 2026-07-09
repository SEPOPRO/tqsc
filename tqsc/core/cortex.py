"""
TQSC v1.0 — Cortex de Confinamiento
Supervisor con descongelación gradual, umbrales dinámicos y HMAC.
"""
import logging, time, json, hashlib, hmac, secrets
from collections import deque
from pathlib import Path
from datetime import datetime

from utils.secure_storage import write as _write

LOG = logging.getLogger("tqsc.cortex")


class CortexDeConfinamiento:
    """Supervisor con descongelación gradual y auto-recovery."""

    def __init__(self, ventana_ciclos: int = 5, max_deg: int = 3, data_dir: str = "data"):
        self.ventana = ventana_ciclos
        self.max_degenerativo = max_deg
        self.historial: deque = deque(maxlen=ventana_ciclos)
        self.congelado = False
        self._modo_seguro = False
        self._descongelando = False
        self._pasos_descongelacion = 0
        self.data_dir = Path(data_dir)
        self._secreto = secrets.token_hex(16)

    def registrar_ciclo(self, metricas: dict) -> str:
        self.historial.append(metricas)
        if self.congelado:
            return "congelado"
        degenerativo = self._evaluar_degeneracion()
        estado = "ok"
        if degenerativo:
            estado = "alerta"
        if self._debe_congelar():
            self.congelado = True
            self._modo_seguro = True
            estado = "congelar"
            LOG.critical("CORTEX: LoRA congelado por auto-envenenamiento!")
            self._notificar_congelamiento()
            self._persistir_evidencia()
        return estado

    def _evaluar_degeneracion(self) -> bool:
        if len(self.historial) < 2: return False
        actual = self.historial[-1]; anterior = self.historial[-2]
        senales = 0
        if actual.get("confianza_promedio", 1) < anterior.get("confianza_promedio", 0): senales += 1
        if actual.get("hipotesis_repetidas") and actual.get("n_fuentes", 1) == 0: senales += 1
        if actual.get("errores", 0) > anterior.get("errores", 0) * 1.5: senales += 1
        if actual.get("confianza_cayendo"): senales += 1
        hora = datetime.now().hour
        umbral = 1 if hora < 6 or hora > 22 else 2
        es_degenerativo = senales >= umbral
        actual["_degenerativo"] = es_degenerativo
        return es_degenerativo

    def _debe_congelar(self) -> bool:
        if len(self.historial) < self.max_degenerativo: return False
        ultimos = list(self.historial)[-self.max_degenerativo:]
        return all(h.get("_degenerativo") for h in ultimos)

    def descongelar_gradual(self) -> str:
        if not self.congelado: return "no_congelado"
        if not self._descongelando:
            self._descongelando = True
            self._pasos_descongelacion = 0
            LOG.warning("Cortex: Fase 1/3")
            return "fase_1_reducir_tasa"
        self._pasos_descongelacion += 1
        if self._pasos_descongelacion == 1:
            LOG.warning("Cortex: Fase 2/3")
            return "fase_2_inferencia_safe"
        if self._pasos_descongelacion >= 2:
            self.congelado = False
            self._modo_seguro = False
            self._descongelando = False
            self.historial.clear()
            LOG.warning("Cortex: Fase 3/3")
            return "fase_3_completa"
        return "descongelando"

    def descongelar(self) -> bool:
        if not self.congelado: return False
        LOG.warning("Cortex: descongelación forzada")
        self.congelado = False
        self._modo_seguro = False
        self._descongelando = False
        self.historial.clear()
        return True

    def _notificar_congelamiento(self):
        alerta = {"timestamp": datetime.now().isoformat(), "evento": "CORTEX_CONFINAMIENTO",
                  "accion": "LoRA congelado", "ultimos_ciclos": len(self.historial),
                  "degenerativos": sum(1 for h in self.historial if h.get("_degenerativo"))}
        LOG.critical(": %s", json.dumps(alerta, indent=2))

    def _persistir_evidencia(self):
        data = {"timestamp": datetime.now().isoformat(),
                "historial": [{k: v for k, v in h.items() if k != "_degenerativo"} for h in self.historial]}
        data["hmac"] = hmac.new(self._secreto.encode(),
                                json.dumps(data, sort_keys=True).encode(),
                                hashlib.sha256).hexdigest()[:16]
        _write(self.data_dir / "cortex_evidencia.json", data)

    def estado(self) -> dict:
        return {"congelado": self.congelado, "modo_seguro": self._modo_seguro,
                "descongelando": self._descongelando,
                "ultimos_ciclos": len(self.historial),
                "degenerativos": sum(1 for h in self.historial if h.get("_degenerativo"))}
