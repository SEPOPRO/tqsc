"""
tqsc/deception/storage.py — Almacenamiento persistente SQLite.
Todas las alertas, tokens y eventos persisten en disco.
Thread-safe mediante WAL mode + Lock.
"""
import sqlite3, json, time, threading, os, logging
from typing import Optional
from pathlib import Path
from .models import Alerta, Token

LOG = logging.getLogger("tqsc.deception.storage")

class SQLiteStorage:
    """SQLite-backed storage con WAL mode. Thread-safe."""

    def __init__(self, ruta: str = None):
        self.ruta = ruta or os.path.join(os.environ.get("TQSC_HOME", "data"), "deception.db")
        Path(self.ruta).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._con = sqlite3.connect(self.ruta, check_same_thread=False)
        self._con.execute("PRAGMA journal_mode=WAL")
        self._con.execute("PRAGMA synchronous=NORMAL")
        self._crear_tablas()

    def _crear_tablas(self):
        with self._lock:
            self._con.executescript("""
                CREATE TABLE IF NOT EXISTS alertas (
                    id TEXT PRIMARY KEY, tipo TEXT, componente TEXT,
                    detalle TEXT, severidad TEXT, origen TEXT,
                    ts REAL, integridad TEXT, correlacion_id TEXT
                );
                CREATE TABLE IF NOT EXISTS tokens (
                    id TEXT PRIMARY KEY, tipo TEXT, valor TEXT,
                    ubicacion TEXT, memo TEXT, creado REAL,
                    disparado INTEGER, hash_integridad TEXT
                );
                CREATE TABLE IF NOT EXISTS correlacion (
                    id TEXT PRIMARY KEY, alertas TEXT,
                    patron TEXT, confidence REAL,
                    mitre_attack TEXT, ts REAL, resuelto INTEGER
                );
                CREATE INDEX IF NOT EXISTS idx_alertas_ts ON alertas(ts);
                CREATE INDEX IF NOT EXISTS idx_tokens_tipo ON tokens(tipo);
            """)
            self._con.commit()

    def guardar_alerta(self, alerta: Alerta) -> str:
        with self._lock:
            self._con.execute(
                "INSERT OR REPLACE INTO alertas VALUES (?,?,?,?,?,?,?,?,?)",
                (alerta.id, alerta.tipo, alerta.componente, alerta.detalle,
                 alerta.severidad, alerta.origen, alerta.ts,
                 alerta.integridad, alerta.correlacion_id))
            self._con.commit()
        return alerta.id

    def consultar_alertas(self, tipo: str = "", limite: int = 100, desde_ts: float = 0) -> list[dict]:
        with self._lock:
            if tipo:
                cur = self._con.execute(
                    "SELECT * FROM alertas WHERE tipo=? AND ts>=? ORDER BY ts DESC LIMIT ?",
                    (tipo, desde_ts, limite))
            else:
                cur = self._con.execute(
                    "SELECT * FROM alertas WHERE ts>=? ORDER BY ts DESC LIMIT ?",
                    (desde_ts, limite))
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def guardar_token(self, token: Token) -> str:
        with self._lock:
            self._con.execute(
                "INSERT OR REPLACE INTO tokens VALUES (?,?,?,?,?,?,?,?)",
                (token.id, token.tipo, token.valor, token.ubicacion,
                 token.memo, token.creado, int(token.disparado),
                 token.hash_integridad))
            self._con.commit()
        return token.id

    def actualizar_estado(self, token_id: str, estado: str):
        """Actualiza el estado de un token (disparado, ignorado, etc.)."""
        with self._lock:
            disparado = 1 if estado == "disparado" else 0
            self._con.execute(
                "UPDATE tokens SET disparado=? WHERE id=?",
                (disparado, token_id))
            self._con.commit()

    def obtener_token_por_valor(self, valor: str) -> Optional[dict]:
        with self._lock:
            cur = self._con.execute("SELECT id, tipo, ubicacion, disparado, valor FROM tokens WHERE valor=? AND disparado=0", (valor,))
            row = cur.fetchone()
            if row:
                cols = [d[0] for d in cur.description]
                return dict(zip(cols, row))
            return None

    def contar_alertas(self, desde_ts: float = 0) -> int:
        with self._lock:
            cur = self._con.execute("SELECT COUNT(*) FROM alertas WHERE ts>=?", (desde_ts,))
            return cur.fetchone()[0]

    def cerrar(self):
        with self._lock:
            self._con.close()
