"""
TQSC v1.0 — IPC Real entre Nodos Blockchain
Comunicación via TCP sockets con heartbeat, timeouts, y autenticación HMAC.
Cada nodo corre un servidor ligero en segundo plano.
"""
import json, socket, threading, time, hmac, hashlib, secrets, logging, os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

LOG = logging.getLogger("tqsc.blockchain.ipc")

TQSC_TEST = os.environ.get("TQSC_TEST_MODE") == "1"
IPC_PORT_BASE = 19000  # puerto base para nodos (nodo 0 = 19000, nodo 1 = 19001, etc.)
HEARTBEAT_INTERVAL = 10  # segundos
HEARTBEAT_TIMEOUT = 30  # segundos sin heartbeat = nodo caído


class NodoRemoto:
    """Conexión a un nodo remoto via TCP."""

    def __init__(self, nodo_id: str, host: str = "127.0.0.1", puerto: Optional[int] = None, secreto: str = ""):
        self.id = nodo_id
        self.host = host
        self.puerto = puerto or IPC_PORT_BASE + hash(nodo_id) % 1000
        self.secreto = secreto or secrets.token_hex(16)
        self.ultimo_heartbeat: Optional[datetime] = None
        self.score: float = 1.0
        self._socket: Optional[socket.socket] = None

    def conectar(self) -> bool:
        if TQSC_TEST: return True
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(5)
            self._socket.connect((self.host, self.puerto))
            self.ultimo_heartbeat = datetime.now()
            return True
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            LOG.warning("Nodo %s no disponible: %s", self.id, e)
            return False

    def enviar(self, mensaje: dict) -> Optional[dict]:
        if TQSC_TEST:
            return {"status": "ok", "respuesta": f"test_{self.id[:8]}"}
        if not self._socket:
            if not self.conectar(): return None
        try:
            payload = json.dumps(mensaje).encode()
            checksum = hmac.new(self.secreto.encode(), payload, hashlib.sha256).hexdigest()[:8]
            paquete = json.dumps({"data": mensaje, "hmac": checksum}).encode() + b"\n"
            self._socket.sendall(paquete)
            respuesta = self._socket.recv(65536)
            if respuesta:
                self.ultimo_heartbeat = datetime.now()
                return json.loads(respuesta.decode())
        except (socket.timeout, ConnectionError, json.JSONDecodeError) as e:
            LOG.warning("Error enviando a %s: %s", self.id, e)
            self._socket = None
        return None

    def cerrar(self):
        if self._socket:
            try: self._socket.close()
            except: pass
            self._socket = None


class ServidorNodo:
    """Servidor TCP ligero para recibir mensajes de otros nodos."""

    def __init__(self, nodo_id: str, puerto: int, secreto: str, data_dir: str = "data"):
        self.id = nodo_id
        self.puerto = puerto
        self.secreto = secreto
        self.data_dir = Path(data_dir)
        self._activo = False
        self._hilo: Optional[threading.Thread] = None
        self.mensajes_recibidos: list[dict] = []
        self.ultimo_heartbeat: Optional[datetime] = None

    def iniciar(self):
        if TQSC_TEST:
            self._activo = True
            return
        self._activo = True
        self._hilo = threading.Thread(target=self._escuchar, daemon=True)
        self._hilo.start()
        LOG.info("ServidorNodo %s escuchando en puerto %d", self.id, self.puerto)

    def _escuchar(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(5)
        try:
            s.bind(("0.0.0.0", self.puerto))
            s.listen(10)
        except OSError as e:
            LOG.warning("ServidorNodo %s: no se pudo bind puerto %d (%s)", self.id, self.puerto, e)
            return
        while self._activo:
            try:
                conn, addr = s.accept()
                threading.Thread(target=self._manejar, args=(conn, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                continue

    def _manejar(self, conn: socket.socket, addr: tuple):
        try:
            data = conn.recv(65536).decode()
            paquete = json.loads(data)
            msg = paquete.get("data", {})
            msg_hmac = paquete.get("hmac", "")
            # Verificar HMAC
            payload = json.dumps(msg).encode()
            esperado = hmac.new(self.secreto.encode(), payload, hashlib.sha256).hexdigest()[:8]
            if msg_hmac != esperado:
                conn.sendall(json.dumps({"status": "error", "razon": "hmac_invalido"}).encode())
                return
            # Procesar según tipo
            tipo = msg.get("tipo", "")
            if tipo == "heartbeat":
                self.ultimo_heartbeat = datetime.now()
                conn.sendall(json.dumps({"status": "ok", "tipo": "heartbeat_ack"}).encode())
            elif tipo == "voto":
                self.mensajes_recibidos.append(msg)
                conn.sendall(json.dumps({"status": "ok", "tipo": "voto_ack"}).encode())
            elif tipo == "challenge":
                nonce = secrets.token_hex(16)
                respuesta = hashlib.sha256(f"{nonce}{self.secreto}".encode()).hexdigest()
                conn.sendall(json.dumps({
                    "status": "ok", "tipo": "challenge_response",
                    "nonce": nonce, "respuesta": respuesta
                }).encode())
            else:
                conn.sendall(json.dumps({"status": "ok", "tipo": "ack"}).encode())
        except (json.JSONDecodeError, ConnectionError) as e:
            LOG.debug("Error manejando conexión de %s: %s", addr, e)
        finally:
            conn.close()

    def detener(self):
        self._activo = False
        LOG.info("ServidorNodo %s detenido", self.id)


class RedBlockchain:
    """Red de nodos blockchain con IPC real."""

    def __init__(self, nodo_local_id: str = "Nodo_A", nodos: Optional[dict[str, str]] = None,
                 data_dir: str = "data"):
        self.nodo_local_id = nodo_local_id
        self.nodos = nodos or {"Nodo_A": "127.0.0.1", "Nodo_B": "127.0.0.1", "Nodo_C": "127.0.0.1"}
        self.data_dir = Path(data_dir)
        self.secreto_local = secrets.token_hex(16)
        self.puerto_local = IPC_PORT_BASE + hash(nodo_local_id) % 1000

        # Servidor local
        self.servidor = ServidorNodo(nodo_local_id, self.puerto_local, self.secreto_local, data_dir)

        # Conexiones a nodos remotos
        self.remotos: dict[str, NodoRemoto] = {}
        for nid, host in self.nodos.items():
            if nid != nodo_local_id:
                self.remotos[nid] = NodoRemoto(nid, host)

        self._activo = False
        self._heartbeat_hilo: Optional[threading.Thread] = None

    def iniciar(self):
        self.servidor.iniciar()
        self._activo = True
        for nodo in self.remotos.values():
            nodo.conectar()
        self._heartbeat_hilo = threading.Thread(target=self._loop_heartbeat, daemon=True)
        self._heartbeat_hilo.start()
        LOG.info("RedBlockchain: %d nodos remotos", len(self.remotos))

    def _loop_heartbeat(self):
        while self._activo:
            for nid, nodo in self.remotos.items():
                respuesta = nodo.enviar({"tipo": "heartbeat", "origen": self.nodo_local_id})
                if respuesta and respuesta.get("status") == "ok":
                    nodo.ultimo_heartbeat = datetime.now()
                    nodo.score = min(1.0, nodo.score + 0.05)
                else:
                    nodo.score = max(0.0, nodo.score - 0.1)
                    if nodo.score < 0.3:
                        LOG.warning("Nodo %s CAIDO (score=%.2f)", nid, nodo.score)
            time.sleep(HEARTBEAT_INTERVAL)

    def enviar_voto(self, propuesta: dict) -> dict:
        """Envía una propuesta de voto a todos los nodos y recoge respuestas."""
        resultados = {}
        for nid, nodo in self.remotos.items():
            respuesta = nodo.enviar({
                "tipo": "voto", "origen": self.nodo_local_id,
                "propuesta": propuesta,
                "timestamp": datetime.now().isoformat(),
            })
            resultados[nid] = respuesta
        return resultados

    def lanzar_desafio(self, nodo_id: str) -> Optional[dict]:
        """Lanza un desafío criptográfico a un nodo específico."""
        nodo = self.remotos.get(nodo_id)
        if not nodo: return None
        return nodo.enviar({"tipo": "challenge", "origen": self.nodo_local_id})

    def nodos_activos(self) -> list[str]:
        return [nid for nid, nodo in self.remotos.items()
                if nodo.ultimo_heartbeat and datetime.now() - nodo.ultimo_heartbeat < timedelta(seconds=HEARTBEAT_TIMEOUT)]

    def detener(self):
        self._activo = False
        self.servidor.detener()
        for nodo in self.remotos.values():
            nodo.cerrar()

    def estado(self) -> dict:
        return {
            "nodo_local": self.nodo_local_id,
            "puerto_local": self.puerto_local,
            "nodos_remotos": len(self.remotos),
            "nodos_activos": len(self.nodos_activos()),
            "test_mode": TQSC_TEST,
            "mensajes_recibidos": len(self.servidor.mensajes_recibidos),
        }
