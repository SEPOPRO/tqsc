"""
tqsc/utils/identity.py — AC-2: Identidades + SC-12: Rotación de claves + CM-2: Línea base.
Cada núcleo tiene un certificado firmado por CA, con rotación automática.
"""
import logging, os, json, hashlib, hmac, time
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional
from utils.tls import TLSWrapper, _cert_path, _key_path, _ca_cert_path

LOG = logging.getLogger("tqsc.identity")
ROTATION_DAYS = int(os.environ.get("TQSC_KEY_ROTATION_DAYS", "90"))


class Identity:
    """Identidad de un núcleo: certificado + metadatos + rotación."""

    def __init__(self, nombre: str, role: str = "nucleo",
                 cert_pem: bytes = None, key_pem: bytes = None):
        self.nombre = nombre
        self.role = role
        self._cert = cert_pem
        self._key = key_pem
        self._inicializado = False
        self._tls: Optional[TLSWrapper] = None
        self._creado = time.time()

    @property
    def activa(self) -> bool:
        return self._cert is not None and self._key is not None

    @property
    def necesita_rotacion(self) -> bool:
        """True si el certificado tiene más de ROTATION_DAYS días."""
        return time.time() - self._creado > ROTATION_DAYS * 86400

    def inicializar(self, ca_cert: bytes = None):
        if self.activa:
            return
        try:
            if ca_cert is None:
                ca_cert = _ca_cert_path().read_bytes()
            try:
                self._cert = _cert_path(self.nombre).read_bytes()
                self._key = _key_path(self.nombre).read_bytes()
            except FileNotFoundError:
                from utils.tls import generar_cert_servicio
                ca_key = (_ca_cert_path().parent / "ca.key").read_bytes()
                ca_cert_data = _ca_cert_path().read_bytes()
                generar_cert_servicio(self.nombre, ca_key, ca_cert_data)
                self._cert = _cert_path(self.nombre).read_bytes()
                self._key = _key_path(self.nombre).read_bytes()
            self._tls = TLSWrapper(ca_cert, self._cert, self._key)
            self._inicializado = True
            LOG.info("Identity: %s (%s) — certificado cargado", self.nombre, self.role)
        except (FileNotFoundError, OSError) as e:
            LOG.warning("Identity: %s — sin certificado (%s)", self.nombre, e)

    def rotar(self, ca_key: bytes = None, ca_cert: bytes = None):
        """Regenera certificado (rotación SC-12)."""
        from utils.tls import generar_cert_servicio, generar_ca
        if ca_key is None or ca_cert is None:
            ca_key = (_ca_cert_path().parent / "ca.key").read_bytes()
            ca_cert = _ca_cert_path().read_bytes()
        generar_cert_servicio(self.nombre, ca_key, ca_cert, sobrescribir=True)
        self._cert = _cert_path(self.nombre).read_bytes()
        self._key = _key_path(self.nombre).read_bytes()
        self._tls = TLSWrapper(ca_cert, self._cert, self._key)
        self._creado = time.time()
        LOG.info("Identity: %s — certificado rotado", self.nombre)

    def fingerprint(self) -> str:
        if not self._cert:
            return "0" * 64
        return hashlib.sha256(self._cert).hexdigest()

    def firmar(self, datos: dict) -> str:
        raw = json.dumps(datos, sort_keys=True).encode()
        hmac_key = hashlib.sha256(self._key).digest() if self._key else b""
        return hmac.new(hmac_key, raw, hashlib.sha256).hexdigest()[:16]

    def tls_context(self, modo: str = "server"):
        if not self._tls:
            return None
        return self._tls.ssl_context()


class IdentityManager:
    """Gestor de identidades con verificación de línea base."""

    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self._identidades: dict[str, Identity] = {}
        self._ca_cert: Optional[bytes] = None
        self._baseline: dict = {}

    def registrar(self, nombre: str, role: str = "nucleo",
                  cert_pem: bytes = None, key_pem: bytes = None) -> Identity:
        ident = Identity(nombre, role, cert_pem, key_pem)
        if self._ca_cert:
            ident.inicializar(self._ca_cert)
        else:
            try:
                ident.inicializar()
                self._ca_cert = _ca_cert_path().read_bytes()
            except Exception:
                pass
        self._identidades[nombre] = ident
        if ident.activa:
            self._baseline[nombre] = {"fingerprint": ident.fingerprint(),
                                      "role": role}
        return ident

    def obtener(self, nombre: str) -> Optional[Identity]:
        return self._identidades.get(nombre)

    def verificar_firma(self, identidad: str, datos: dict, firma: str) -> bool:
        ident = self._identidades.get(identidad)
        if not ident:
            return False
        raw = json.dumps(datos, sort_keys=True).encode()
        hmac_key = hashlib.sha256(ident._key).digest() if ident._key else b""
        esperado = hmac.new(
            hmac_key, raw, hashlib.sha256
        ).hexdigest()[:16]
        return hmac.compare_digest(firma, esperado)

    def verificar_baseline(self) -> list[str]:
        """CM-2: Verifica que todas las identidades activas coincidan con línea base."""
        cambios = []
        for nombre, baseline in self._baseline.items():
            ident = self._identidades.get(nombre)
            if not ident:
                cambios.append(f"{nombre}: identidad eliminada")
                continue
            if ident.fingerprint() != baseline.get("fingerprint"):
                cambios.append(f"{nombre}: FINGERPRINT CAMBIÓ (posible compromiso)")
            if ident.role != baseline.get("role"):
                cambios.append(f"{nombre}: role cambiado ({ident.role})")
        return cambios

    def rotar_vencidas(self) -> list[str]:
        """SC-12: Rota todas las identidades con certificados vencidos."""
        rotadas = []
        for nombre, ident in self._identidades.items():
            if ident.necesita_rotacion:
                try:
                    ident.rotar()
                    rotadas.append(nombre)
                except Exception as e:
                    LOG.error("Rotación falló: %s — %s", nombre, e)
        if rotadas:
            LOG.info("Rotación: %d certificados rotados", len(rotadas))
        return rotadas

    def listar(self) -> list[dict]:
        return [{"nombre": n, "role": i.role, "activa": i.activa,
                 "fingerprint": i.fingerprint(),
                 "rotacion_pendiente": i.necesita_rotacion}
                for n, i in self._identidades.items()]

    def estado(self) -> dict:
        return {"identidades": len(self._identidades),
                "activas": sum(1 for i in self._identidades.values() if i.activa),
                "rotacion_pendiente": sum(1 for i in self._identidades.values()
                                           if i.necesita_rotacion)}


_mgr: Optional[IdentityManager] = None


def obtener_manager() -> IdentityManager:
    global _mgr
    if _mgr is None:
        data_dir = os.environ.get("TQSC_HOME", "data")
        _mgr = IdentityManager(data_dir)
    return _mgr
