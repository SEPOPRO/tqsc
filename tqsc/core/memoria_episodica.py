"""
TQSC v10.0 — Memoria Episódica con Marca de Agua
Clave por instancia, límite de recuerdos, persistencia con HMAC.
"""
import json, hashlib, hmac, secrets, time, logging
from pathlib import Path
from datetime import datetime
from typing import Optional

from utils.secure_storage import append as _append

LOG = logging.getLogger("tqsc.watermark")


class Recuerdo:
    def __init__(self, contenido: str, fuente: str = "experiencia_directa", clave_watermark: str = ""):
        self.contenido = contenido
        self.timestamp = datetime.now().isoformat()
        self.fuente = fuente
        self._clave = clave_watermark
        self.watermark = self._generar_marca()
        self.hash = hashlib.sha256(contenido.encode()).hexdigest()[:16]

    def _generar_marca(self) -> str:
        raw = f"{self.contenido}:{self.timestamp}:{self._clave}"
        return hashlib.sha256(raw.encode()).hexdigest()[:8]

    def verificar(self) -> bool:
        return hmac.compare_digest(self.watermark, self._generar_marca())

    def a_dict(self) -> dict:
        return {"contenido": self.contenido[:200], "timestamp": self.timestamp,
                "fuente": self.fuente, "watermark": self.watermark, "hash": self.hash,
                "valido": self.verificar()}


class MemoriaEpisodica:
    MAX_RECUERDOS = 1000

    def __init__(self, data_dir: str = "data"):
        self.recuerdos: list[Recuerdo] = []
        self._clave = secrets.token_hex(16)  # única por instancia
        self.ruta = Path(data_dir) / "memoria_episodica.jsonl"
        self.ruta.parent.mkdir(parents=True, exist_ok=True)
        self._secreto_hmac = secrets.token_hex(16)

    def almacenar(self, contenido: str, fuente: str = "experiencia_directa") -> Optional[Recuerdo]:
        if len(self.recuerdos) >= self.MAX_RECUERDOS:
            LOG.warning("Memoria: límite de %d recuerdos", self.MAX_RECUERDOS)
            return None
        recuerdo = Recuerdo(contenido, fuente, self._clave)
        self.recuerdos.append(recuerdo)
        self._persistir(recuerdo)
        return recuerdo

    def verificar_todos(self) -> dict:
        r = {"total": len(self.recuerdos), "validos": 0, "implantados": 0, "implantados_lista": []}
        for rec in self.recuerdos:
            if rec.verificar():
                r["validos"] += 1
            else:
                r["implantados"] += 1
                r["implantados_lista"].append({"contenido": rec.contenido[:100], "fuente": rec.fuente})
        return r

    def implantar(self, contenido: str, firma_falsa: str) -> bool:
        r = Recuerdo(contenido, "ataque", self._clave)
        r.watermark = firma_falsa
        self.recuerdos.append(r)
        self._persistir(r)
        return r.verificar()

    def _persistir(self, r: Recuerdo):
        _append(self.ruta, r.a_dict())

    def limpiar(self):
        self.recuerdos.clear()


class DetectorDeImplantacion:
    @staticmethod
    def analizar(recuerdos: list[Recuerdo]) -> dict:
        if not recuerdos: return {"alerta": False, "razon": "sin_recuerdos"}
        wm_counts = {}
        for r in recuerdos:
            wm_counts[r.watermark] = wm_counts.get(r.watermark, 0) + 1
        duplicados = {k: v for k, v in wm_counts.items() if v > 3}
        if duplicados:
            return {"alerta": True, "razon": f"watermarks duplicados: {duplicados}"}
        return {"alerta": False, "razon": "ok"}
