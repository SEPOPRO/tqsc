"""
TQSC v10.0 — Protocolo de Paz entre Agentes
Handshake criptográfico con renovación de claves y anti-replay.
"""
import json, time, hashlib, hmac, secrets, logging
from datetime import datetime, timedelta
from typing import Optional

LOG = logging.getLogger("tqsc.paz")


class IdentidadAgente:
    def __init__(self, nombre: str):
        self.nombre = nombre
        self.id = secrets.token_hex(16)
        self._secreto = secrets.token_hex(32)
        self.llave_publica = hashlib.sha256(f"{self.id}:{self._secreto}".encode()).hexdigest()
        self.ultima_rotacion = time.time()
        LOG.info("Agente %s creado: id=%s...", nombre, self.id[:8])

    def firmar(self, mensaje: str) -> str:
        raw = f"{mensaje}:{self.id}:{int(time.time())}".encode()
        return hmac.new(self._secreto.encode(), raw, hashlib.sha256).hexdigest()

    def rotar_secreto(self):
        self._secreto = secrets.token_hex(32)
        self.llave_publica = hashlib.sha256(f"{self.id}:{self._secreto}".encode()).hexdigest()
        self.ultima_rotacion = time.time()
        LOG.info("Agente %s: secreto rotado", self.nombre)


class MensajePaz:
    def __init__(self, origen: IdentidadAgente, tipo: str, contenido: str, destino: str = "", nonce: str = ""):
        self.timestamp = datetime.now().isoformat()
        self.origen_id = origen.id
        self.origen_nombre = origen.nombre
        self.tipo = tipo; self.contenido = contenido; self.destino = destino
        self.nonce = nonce or secrets.token_hex(8)
        self.firma = self._calcular_firma(origen)

    def _calcular_firma(self, agente: IdentidadAgente) -> str:
        raw = json.dumps({"origen_id": self.origen_id, "tipo": self.tipo, "contenido": self.contenido,
                          "destino": self.destino, "timestamp": self.timestamp, "nonce": self.nonce},
                         sort_keys=True).encode()
        return hmac.new(agente._secreto.encode(), raw, hashlib.sha256).hexdigest()

    def verificar(self, agente: IdentidadAgente) -> bool:
        return hmac.compare_digest(self.firma, self._calcular_firma(agente))


class RegistroAgentes:
    def __init__(self):
        self.agentes: dict[str, IdentidadAgente] = {}
        self.estado: dict[str, str] = {}
        self._nonces_usados: set[str] = set()
        self._max_mensajes = 1000

    def registrar(self, agente: IdentidadAgente):
        self.agentes[agente.id] = agente
        self.estado[agente.id] = "confiable"

    def aislar(self, agente_id: str, razon: str):
        self.estado[agente_id] = "aislado"
        LOG.warning("Agente %s aislado: %s", agente_id[:8], razon)

    def es_confiable(self, agente_id: str) -> bool:
        return self.estado.get(agente_id) == "confiable"

    def verificar_mensaje(self, mensaje: MensajePaz) -> bool:
        # Anti-replay: nonce ya usado
        if mensaje.nonce in self._nonces_usados:
            LOG.warning("Replay detectado: nonce %s", mensaje.nonce[:8])
            return False
        agente = self.agentes.get(mensaje.origen_id)
        if not agente: return False
        if not self.es_confiable(mensaje.origen_id): return False
        if not mensaje.verificar(agente):
            self.aislar(mensaje.origen_id, "firma_invalida")
            return False
        self._nonces_usados.add(mensaje.nonce)
        if len(self._nonces_usados) > 10000:
            self._nonces_usados = set(list(self._nonces_usados)[-5000:])
        return True


class ProtocoloPaz:
    MAX_MENSAJES = 1000

    def __init__(self, agente_local: IdentidadAgente):
        self.local = agente_local
        self.registro = RegistroAgentes()
        self.registro.registrar(agente_local)
        self.mensajes_recibidos: list[MensajePaz] = []

    def enviar(self, destino_id: str, tipo: str, contenido: str) -> MensajePaz:
        return MensajePaz(self.local, tipo, contenido, destino_id)

    def recibir(self, mensaje: MensajePaz) -> Optional[str]:
        if len(self.mensajes_recibidos) >= self.MAX_MENSAJES:
            LOG.warning("ProtocoloPaz: límite de mensajes alcanzado")
            return None
        if not self.registro.verificar_mensaje(mensaje):
            return None
        self.mensajes_recibidos.append(mensaje)
        return mensaje.contenido

    def estado(self) -> dict:
        return {"agente_local": self.local.nombre,
                "agentes_conocidos": len(self.registro.agentes),
                "agentes_confiables": sum(1 for e in self.registro.estado.values() if e == "confiable"),
                "mensajes_recibidos": len(self.mensajes_recibidos)}
