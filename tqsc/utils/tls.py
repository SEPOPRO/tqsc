"""
TQSC v2.0 — mTLS local entre servicios.
CA autogenerada + certificados por servicio.
"""
import os, socket, ssl, logging, datetime, tempfile
from pathlib import Path
from typing import Optional, Callable
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

LOG = logging.getLogger("tqsc.tls")
CERTS_DIR = Path(os.environ.get("TQSC_HOME", "data")) / "certs"


def _key_path(n: str) -> Path: return CERTS_DIR / f"{n}.key"
def _cert_path(n: str) -> Path: return CERTS_DIR / f"{n}.crt"


def generar_ca(sobrescribir: bool = False) -> tuple[bytes, bytes]:
    if not sobrescribir and _key_path("ca").exists() and _cert_path("ca").exists():
        return _key_path("ca").read_bytes(), _cert_path("ca").read_bytes()
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(65537, 4096, default_backend())
    sub = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "MX"),
                     x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TQSC"),
                     x509.NameAttribute(NameOID.COMMON_NAME, "TQSC Root CA")])
    cert = (x509.CertificateBuilder().subject_name(sub).issuer_name(sub)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256(), default_backend()))
    kp = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    cp = cert.public_bytes(serialization.Encoding.PEM)
    _key_path("ca").write_bytes(kp); _cert_path("ca").write_bytes(cp)
    LOG.info("CA generada"); return kp, cp


def generar_cert_servicio(nombre: str, ca_key_pem: bytes, ca_cert_pem: bytes,
                          sobrescribir: bool = False) -> tuple[bytes, bytes]:
    if not sobrescribir and _key_path(nombre).exists() and _cert_path(nombre).exists():
        return _key_path(nombre).read_bytes(), _cert_path(nombre).read_bytes()
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    ca_key = serialization.load_pem_private_key(ca_key_pem, None, default_backend())
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem, default_backend())
    key = rsa.generate_private_key(65537, 2048, default_backend())
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "MX"),
                                     x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TQSC"),
                                     x509.NameAttribute(NameOID.COMMON_NAME, nombre)]))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(nombre),
                           x509.DNSName(f"{nombre}.tqsc_internal"), x509.DNSName("localhost")]), critical=False)
            .sign(ca_key, hashes.SHA256(), default_backend()))
    kp = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    cp = cert.public_bytes(serialization.Encoding.PEM)
    _key_path(nombre).write_bytes(kp); _cert_path(nombre).write_bytes(cp)
    LOG.info("Certificado: %s", nombre); return kp, cp


def generar_todos():
    ca_k, ca_c = generar_ca()
    for s in ["tqsc-supervisor", "tqsc-ia", "tqsc-blockchain", "tqsc-defense",
              "tqsc-quantum", "tqsc-entropy", "tqsc-cortex", "tqsc-memoria",
              "tqsc-paz", "tqsc-honeypot", "localhost"]:
        generar_cert_servicio(s, ca_k, ca_c)
    LOG.info("%d certificados generados", 11)


class TLSWrapper:
    def __init__(self, ca_cert_pem: bytes = None, cert_pem: bytes = None,
                 key_pem: bytes = None, nombre: str = ""):
        if ca_cert_pem is None: ca_cert_pem = _cert_path("ca").read_bytes()
        if cert_pem is None and nombre:
            cert_pem = _cert_path(nombre).read_bytes()
            key_pem = _key_path(nombre).read_bytes()
        self._ca = ca_cert_pem; self._cert = cert_pem; self._key = key_pem
        self._cleanup = []

    def _ctx(self, modo: ssl.Purpose) -> ssl.SSLContext:
        ctx = ssl.create_default_context(modo)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cadata=self._ca.decode())
        cf = tempfile.NamedTemporaryFile(delete=False, suffix='.crt', mode='wb'); cf.write(self._cert); cf.close()
        kf = tempfile.NamedTemporaryFile(delete=False, suffix='.key', mode='wb'); kf.write(self._key); kf.close()
        self._cleanup.extend([cf.name, kf.name])
        ctx.load_cert_chain(cf.name, kf.name)
        return ctx

    def escuchar(self, puerto: int, handler: Callable, host: str = "0.0.0.0") -> socket.socket:
        ctx = self._ctx(ssl.Purpose.CLIENT_AUTH)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, puerto)); s.listen(10)
        LOG.info("TLS escuchando en %s:%d", host, puerto)
        return ctx.wrap_socket(s, server_side=True)

    def conectar(self, host: str, puerto: int, timeout: int = 10) -> Optional[ssl.SSLSocket]:
        try:
            ctx = self._ctx(ssl.Purpose.SERVER_AUTH)
            s = socket.create_connection((host, puerto), timeout=timeout)
            sni = 'localhost' if host in ('127.0.0.1', '::1', '0.0.0.0') else host
            return ctx.wrap_socket(s, server_hostname=sni)
        except (socket.timeout, ConnectionRefusedError, ssl.SSLError, OSError) as e:
            LOG.warning("TLS falló a %s:%d: %s", host, puerto, e)
            return None

    def __del__(self):
        for f in self._cleanup:
            try: os.unlink(f)
            except: pass


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    generar_todos()
    print("mTLS certs en data/certs/")
