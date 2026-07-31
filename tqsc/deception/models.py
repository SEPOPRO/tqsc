"""
tqsc/deception/models.py — Modelos de datos con typing.
"""
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime
import uuid


@dataclass
class Token:
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    tipo: str = ""
    valor: str = ""
    ubicacion: str = ""
    memo: str = ""
    creado: float = 0.0
    disparado: bool = False
    hash_integridad: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Alerta:
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    tipo: str = ""
    componente: str = ""
    detalle: str = ""
    severidad: str = "media"
    origen: str = ""
    ts: float = 0.0
    integridad: str = ""
    correlacion_id: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    def firmar(self, secreto: str):
        import hmac, hashlib, json
        raw = json.dumps(asdict(self), sort_keys=True)
        self.integridad = hmac.new(secreto.encode(), raw.encode(), hashlib.sha256).hexdigest()[:32]


@dataclass
class EventoCorrelacion:
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    alertas: list[str] = field(default_factory=list)
    patron: str = ""
    confidence: float = 0.0
    mitre_attack: list[str] = field(default_factory=list)
    ts: float = 0.0
    resuelto: bool = False
