"""
TQSC v1.0 — OctaNucleo
Núcleo base del sistema IA autoevolutivo OctaRCQ-X8.
"""
import hashlib, hmac, secrets
import collections
from datetime import datetime
from typing import Any, Optional


MAX_BUFFER = 1000


class OctaNucleo:
    """Unidad cognitiva base del sistema OctaRCQ-X8."""

    def __init__(self, nombre: str, nucleos_hijos: int = 0):
        self.nombre = nombre
        self.estado = "activo"
        self.buffer: list[str] = []
        self.adn_hash: list[str] = []  # SHA256 en vez de hash()
        self.historial: list[str] = []
        self.contexto: dict[str, Any] = {}
        self.shadow: Optional["OctaNucleo"] = None
        self.hijos = [OctaNucleo(f"{nombre}_{i+1}") for i in range(nucleos_hijos)]

    def recibir(self, patron: str, contexto: Optional[dict] = None):
        if self.estado == "aislado":
            return
        if len(self.buffer) >= MAX_BUFFER:
            import logging
            logging.getLogger("tqsc.core").warning("Buffer lleno: %s (%d items)", self.nombre, MAX_BUFFER)
            return
        self.buffer.append(patron)
        if contexto:
            self.contexto[patron] = contexto
        self._mutar(f"entrada: {patron[:60]}")

    def procesar(self) -> list[str]:
        if self.estado != "activo":
            return []
        resultados = list(self.buffer)
        self.buffer.clear()
        self._mutar(f"procesados: {len(resultados)} patrones")
        return resultados

    def aislar(self):
        self.estado = "aislado"
        self._mutar("aislado")

    def activar(self):
        self.estado = "activo"
        self._mutar("reactivado")

    def clonar_shadow(self) -> Optional["OctaNucleo"]:
        if self.shadow:
            return self.shadow
        if len([h for h in self.hijos if h.nombre.endswith("_shadow")]) >= 3:
            return None
        self.shadow = OctaNucleo(f"{self.nombre}_shadow")
        self.shadow.adn_hash = list(self.adn_hash)
        self.shadow.historial = list(self.historial)
        return self.shadow

    def _mutar(self, evento: str):
        """Generates a SHA256 hash of event_name + timestamp and appends to adn_hash list. Named 'mutation' metaphorically."""
        firma = hashlib.sha256(f"{evento}{datetime.now().isoformat()}".encode()).hexdigest()[:16]
        self.adn_hash.append(firma)
        self.historial.append(f"[{datetime.now().isoformat()}] {evento}")

    def snapshot(self) -> dict:
        return {
            "nombre": self.nombre,
            "estado": self.estado,
            "buffer_size": len(self.buffer),
            "adn_length": len(self.adn_hash),
            "ultimo_hash": self.adn_hash[-1] if self.adn_hash else None,
            "shadow_activo": self.shadow is not None,
            "hijos": [h.nombre for h in self.hijos],
        }


class PatternGate:
    """Filtra patrones con lista expandida y detección por encoding."""

    BLOQUEADOS = [
        "bloqueado", "恶意", "<script", "alert(", "onerror=", "onload=",
        "javascript:", "onclick=", "onfocus=", "onmouseover",
        "../", "..\\", "etc/passwd", "etc/shadow",
        ";rm ", ";drop ", ";delete ", "||rm ", "|rm ",
        "system(", "exec(", "passthru(", "shell_exec(", "eval(",
        "select * from", "union select", "information_schema",
        "%00", "%0d%0a", "cmd.exe", "powershell.exe",
        "boot.ini", "win.ini", ".env",
    ]

    @staticmethod
    def validar(patron: str) -> bool:
        p = patron.lower()
        # URL decode recursivo (hasta 5 capas)
        import urllib.parse
        for _ in range(20):
            prev = p
            try:
                p = urllib.parse.unquote(p)
            except Exception:
                break
            if p == prev:
                break
        # Unicode normalization
        import unicodedata
        p = unicodedata.normalize("NFKC", p)
        # Path traversal normalization: ....// → ../ (antes del check)
        while "...." in p or "..." in p or "////" in p:
            p = p.replace("....", "..").replace("...", "..").replace("////", "/").replace("\\\\", "\\")
        # Check bloqueados DESPUÉS de normalizar path traversal
        bloqueado = any(b in p for b in PatternGate.BLOQUEADOS)
        if bloqueado:
            return False
        # Hex decode attempt (solo si pasó el check básico)
        try:
            p2 = bytes.fromhex(p).decode("utf-8", errors="ignore").lower()
            if any(b in p2 for b in PatternGate.BLOQUEADOS):
                return False
        except (ValueError, UnicodeDecodeError):
            pass
        return True


class PreImpactSynthesizer:
    """Keyword-based substring matching for threats, not predictive analysis. Anticipa amenazas con score normalizado."""

    SEÑALES = {
        "destructivas": (1.0, ["drop ", "delete ", "shutdown", "fork", "exec", "rm ", "format", "wipe"]),
        "privilegios":  (0.7, ["sudo", "chmod", "chown", "escalate", "admin"]),
        "red":          (0.5, ["scan", "nmap", "connect", "proxy", "tunnel", "ddos"]),
        "datos":        (0.6, ["exfil", "upload", "download", "copy ", "scp ", "rsync"]),
        "shellcode":    (0.9, ["\x90\x90", "\xcc\xcc", "\x31\xc0", "\xeb\xfe", "nop"]),
    }

    def __init__(self, umbral_base: float = 0.30):
        self.umbral = umbral_base
        self.historial: list[dict] = []

    def anticipar(self, patron: str) -> bool:
        p_lower = patron.lower()
        score_max = 0.0
        categoria_max = ""
        for cat, (peso, senales) in self.SEÑALES.items():
            for s in senales:
                if s in p_lower:
                    score_actual = peso * (0.6 if cat in ("destructivas", "shellcode") else 0.4)
                    score_max = max(score_max, score_actual)
                    categoria_max = cat

        if len(self.historial) > 10:
            fp = sum(1 for h in self.historial[-20:] if h.get("fp", False))
            tasa_fp = fp / min(20, len(self.historial[-20:]))
            umbral_efectivo = min(0.5, self.umbral + tasa_fp * 0.15)
        else:
            umbral_efectivo = self.umbral

        decision = score_max >= umbral_efectivo
        self.historial.append({"patron": patron[:60], "score": round(score_max, 3),
                                "categoria": categoria_max, "decision": decision})
        return decision

    def reportar_falso_positivo(self):
        if self.historial:
            self.historial[-1]["fp"] = True

    def estado(self) -> dict:
        return {"umbral_base": self.umbral, "decisiones": len(self.historial),
                "alertas": sum(1 for h in self.historial if h["decision"]),
                "ultima_categoria": self.historial[-1]["categoria"] if self.historial else None}


class GhostMemoryZone:
    """Zona de memoria con firma HMAC para detectar inyección."""

    def __init__(self, max_size: int = 100, secreto: str = ""):
        self.zona = collections.deque()
        self.max_size = max_size
        self._secreto = secreto or secrets.token_hex(8)
        self._firmas: list[str] = []

    def evacuar(self, patron: str):
        self.zona.append(patron)
        self._firmas.append(hmac.new(self._secreto.encode(), patron.encode(), hashlib.sha256).hexdigest()[:8])
        if len(self.zona) > self.max_size:
            self.zona.popleft()
            self._firmas.pop(0)

    def recuperar(self) -> list[str]:
        resultado = list(self.zona)
        self.zona.clear()
        self._firmas.clear()
        return resultado

    def verificar_integridad(self) -> bool:
        for i, p in enumerate(self.zona):
            if i >= len(self._firmas):
                return False
            esperado = hmac.new(self._secreto.encode(), p.encode(), hashlib.sha256).hexdigest()[:8]
            if self._firmas[i] != esperado:
                return False
        return True
