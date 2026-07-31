"""
tqsc/deception/entropy_matcher.py — Entropy Matcher del ABH Engine.
Asegura que los honeytokens generados tengan la misma distribución
estadística que los tokens/credenciales reales del entorno.
"""
import math, logging, statistics
from typing import Optional

LOG = logging.getLogger("tqsc.deception.entropy_matcher")


class EntropyMatcher:
    """Verifica y ajusta la entropía de honeytokens para que coincidan
    con la distribución de datos reales del entorno.

    Hace que los tokens sean indetectables por análisis estadístico:
    H(token) ≈ μ_real dentro de 2σ_real
    """

    def __init__(self, sigma_threshold: float = 2.0, max_iterations: int = 10):
        self.sigma_threshold = sigma_threshold
        self.max_iterations = max_iterations
        self._baseline_mean: Optional[float] = None
        self._baseline_std: Optional[float] = None
        self._sample_count: int = 0

    # ─────────────────────────────────────────────
    # Cálculo de entropía
    # ─────────────────────────────────────────────

    @staticmethod
    def shannon_entropy(text: str) -> float:
        """Calcula H(X) = -Σ P(x)·log₂P(x) para un texto."""
        if not text:
            return 0.0
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        n = len(text)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    @staticmethod
    def charset_entropy(text: str) -> float:
        """Mide diversidad del charset usado: ratio de chars únicos."""
        if not text:
            return 0.0
        return len(set(text)) / len(text)

    @staticmethod
    def pattern_entropy(text: str) -> float:
        """Detecta patrones repetitivos que delatan generación sintética.
        Penaliza: repeticiones, secuencias predecibles, padding uniforme."""
        if len(text) < 4:
            return 1.0
        repeats = 0
        for i in range(len(text) - 3):
            if text[i:i+3] in text[i+3:]:
                repeats += 1
        # Normalizar: a más repeticiones, menor entropía de patrón
        max_possible = len(text) - 3
        return 1.0 - (repeats / max_possible) if max_possible > 0 else 1.0

    def composite_entropy(self, text: str) -> float:
        """Entropía compuesta ponderada: Shannon + charset + pattern."""
        s = self.shannon_entropy(text)
        c = self.charset_entropy(text)
        p = self.pattern_entropy(text)
        # Normalizar Shannon a [0,1] dividiendo por log₂(|charset|)
        charset_size = len(set(text)) or 1
        s_norm = s / (math.log2(max(charset_size, 2)))
        return (s_norm * 0.5) + (c * 0.3) + (p * 0.2)

    # ─────────────────────────────────────────────
    # Baseline del entorno
    # ─────────────────────────────────────────────

    def calibrate(self, real_samples: list[str]):
        """Calibra el baseline con muestras de tokens REALES del entorno.
        Debe llamarse una vez al inicio con samples del entorno real."""
        if not real_samples:
            LOG.warning("EntropyMatcher: no hay muestras reales para calibrar")
            return

        entropies = [self.composite_entropy(s) for s in real_samples]
        self._baseline_mean = statistics.mean(entropies)
        self._baseline_std = statistics.stdev(entropies) if len(entropies) > 1 else 0.05
        self._sample_count = len(real_samples)

        LOG.info("EntropyMatcher: calibrado μ=%.4f σ=%.4f (n=%d)",
                 self._baseline_mean, self._baseline_std, self._sample_count)

    @property
    def is_calibrated(self) -> bool:
        return self._baseline_mean is not None

    # ─────────────────────────────────────────────
    # Validación y ajuste de tokens
    # ─────────────────────────────────────────────

    def validate(self, token: str) -> dict:
        """Valida un token contra el baseline.
        Retorna: {pass, entropy, z_score, reason}"""
        if not self.is_calibrated:
            return {"pass": True, "entropy": self.composite_entropy(token),
                    "z_score": 0.0, "reason": "no_calibrated"}

        h = self.composite_entropy(token)
        z = (h - self._baseline_mean) / self._baseline_std if self._baseline_std > 0 else 0.0
        is_valid = abs(z) <= self.sigma_threshold

        return {
            "pass": is_valid,
            "entropy": round(h, 4),
            "expected": round(self._baseline_mean, 4),
            "z_score": round(z, 4),
            "reason": "ok" if is_valid else f"z={z:.2f} fuera de ±{self.sigma_threshold}σ",
        }

    def explain(self, token: str) -> dict:
        """Análisis detallado de por qué un token pasa o falla."""
        result = self.validate(token)

        if not result["pass"]:
            if result["z_score"] > 0:
                hint = "demasiada entropía — parece generado por algoritmo criptográfico"
            else:
                hint = "muy poca entropía — demasiado predecible o repetitivo"
            result["hint"] = hint
            # Desglose por métrica
            result["shannon"] = round(self.shannon_entropy(token), 4)
            result["charset"] = round(self.charset_entropy(token), 4)
            result["pattern"] = round(self.pattern_entropy(token), 4)

        return result

    # ─────────────────────────────────────────────
    # Ajuste automático de tokens
    # ─────────────────────────────────────────────

    def adjust(self, token: str, llm_adjust_callback=None) -> str:
        """Ajusta el token iterativamente hasta que pase la validación.
        Si se provee un callback de ajuste (para re-generar con LLM),
        se usa; si no, se aplican transformaciones heurísticas."""
        if not self.is_calibrated:
            return token

        for iteration in range(self.max_iterations):
            validation = self.validate(token)
            if validation["pass"]:
                return token

            if llm_adjust_callback:
                # Pedir al LLM que re-genere con feedback de entropía
                token = llm_adjust_callback(token, validation)
            else:
                # Heurística: añadir/remover chars para ajustar entropía
                token = self._heuristic_adjust(token, validation)

        # Último intento: si aún falla, loggear warning
        final = self.validate(token)
        if not final["pass"]:
            LOG.warning("EntropyMatcher: no se pudo ajustar token tras %d iteraciones (z=%.2f)",
                        self.max_iterations, final["z_score"])
        return token

    def _heuristic_adjust(self, token: str, validation: dict) -> str:
        """Ajuste heurístico simple cuando no hay LLM callback."""
        import secrets, string

        z = validation["z_score"]
        # Si demasiada entropía: añadir caracteres comunes predecibles
        if z > 1.0:
            common = string.ascii_lowercase + string.digits
            # Añadir patrón repetitivo para reducir entropía
            token += secrets.choice(common) * 2
        # Si muy poca entropía: añadir variación
        elif z < -1.0:
            token += secrets.choice(string.ascii_uppercase)
            token += secrets.choice(string.digits)
            token += secrets.choice("!@#$%^&*")
        # Si ok parcial, añadir mezcla sutil
        else:
            token += secrets.choice(string.ascii_lowercase)

        return token

    def estado(self) -> dict:
        return {
            "calibrado": self.is_calibrated,
            "muestras": self._sample_count,
            "media": round(self._baseline_mean, 4) if self._baseline_mean else None,
            "std": round(self._baseline_std, 4) if self._baseline_std else None,
            "sigma": self.sigma_threshold,
        }
