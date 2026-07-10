"""
TQSC v2.0 — World Model Inference Engine
Carga los 13 modelos entrenados y provee predicciones para todos los núcleos.

Uso:
  from ml.inference import WorldModel
  wm = WorldModel()
  estado = wm.extract_features(sistema_state)
  pred = wm.predecir(estado)
  # pred["pi_tipo"] -> "sqli", "scanner", etc.
"""
import logging, os, json
from pathlib import Path
from typing import Optional

LOG = logging.getLogger("tqsc.ml")

TARGETS = [
    "bc_fork", "cd_necesita", "cl_loop", "cx_congelar",
    "en_anomalia", "hm_anomalia", "ij_aceptable", "me_implantacion",
    "oc_shellcode", "pi_accion", "pi_severidad", "pi_tipo", "ps_reflectivo",
]

TIPOS_ATAQUE = {
    0: "brute-force", 1: "dictionary", 2: "scanner", 3: "exploit",
    4: "sqli", 5: "xss", 6: "fuzzing", 7: "rfi", 8: "lfi", 9: "cmd_inject",
    10: "normal", 11: "desconocido",
}

ACCIONES = {0: "bloquear", 1: "engañar", 2: "monitorear", 3: "ignorar"}


class WorldModel:
    """Carga modelos sklearn y provee predicciones para los 9 núcleos."""

    def __init__(self, model_dir: str = "data/ml"):
        self._modelos = None
        self._scaler = None
        self._ruta = Path(model_dir)
        self._cargado = False

    def _cargar(self):
        try:
            import joblib
            self._modelos = joblib.load(self._ruta / "modelos.pkl")
            self._scaler = joblib.load(self._ruta / "scaler.pkl")
            self._cargado = True
            LOG.info("World Model: %d cabezas cargadas (%d features)",
                     len(self._modelos), self._scaler.n_features_in_)
        except Exception as e:
            LOG.warning("World Model: no disponible — %s", e)
            self._cargado = False

    @property
    def disponible(self) -> bool:
        if not self._cargado:
            self._cargar()
        return self._cargado

    def extract_features(self, estado: dict) -> Optional[list]:
        """Convierte estado del sistema en vector de 68 features."""
        try:
            ia = estado.get("ia_core", {})
            df = estado.get("defense", {})
            bc = estado.get("blockchain", {})
            qc = estado.get("classic_crypto", {})
            hp = estado.get("honeypot", {})
            en = estado.get("entropy", {})
            cx = estado.get("cortex", {})
            pz = estado.get("paz", {})
            me = estado.get("memoria", {})

            # IA Core (13 features)
            f = [
                ia.get("octantes_activos", 0) / 8.0,
                ia.get("octantes_aislados", 0) / 8.0,
                ia.get("confianza_promedio", 0.5),
                ia.get("mutaciones", 0),
                ia.get("shadow_activos", 0),
                ia.get("score_loop", 0.0),
                ia.get("ciclos_repetidos", 0),
                ia.get("pattern_transfer", 0),
                ia.get("ghost_memory", 0),
                ia.get("preimpact_severidad", 0.5),
                ia.get("preimpact_confianza", 0.5),
                ia.get("entropia_consenso", 0.9),
                ia.get("sesiones_activas", 0) / 10.0,
            ]

            # Defense (12 features)
            f += [
                df.get("cpu_uso", 0) / 100.0,
                df.get("temp_cpu", 0) / 100.0,
                df.get("memoria_libre", 0) / 8192.0,
                df.get("procesos", 0) / 500.0,
                df.get("hilos_sospechosos", 0) / 10.0,
                df.get("procesos_por_hilo", 0) / 20.0,
                df.get("syscalls_por_min", 0) / 1000.0,
                df.get("cache_hits", 0) / 100.0,
                df.get("pid_analizados", 0) / 100.0,
                df.get("diff_disco_memoria", 0),
                df.get("opcode_nop", 0),
                df.get("opcode_shellcode", 0),
            ]

            # Blockchain (7 features)
            f += [
                bc.get("nodos", 0) / 10.0,
                bc.get("consensos", 0) / 10.0,
                bc.get("desacuerdos", 0) / 5.0,
                bc.get("forks", 0),
                bc.get("nodos_comprometidos", 0) / 5.0,
                bc.get("reputacion_minima", 0.0),
                bc.get("reputacion_maxima", 1.0),
            ]

            # Classic Crypto (5 features)
            f += [
                qc.get("claves_derivadas", 0) / 100.0,
                qc.get("cifrados", 0) / 100.0,
                qc.get("firmas", 0) / 50.0,
                qc.get("verificaciones_fallo", 0),
                qc.get("nonces_usados", 0) / 100.0,
            ]

            # Honeypot (5 features)
            f += [
                hp.get("sesiones_hoy", 0) / 100.0,
                hp.get("ataques_detectados", 0) / 50.0,
                hp.get("tipos_distintos", 0) / 10.0,
                hp.get("herramientas_distintas", 0) / 5.0,
                hp.get("tasa_exito_login", 0.5),
            ]

            # Entropy (6 features)
            f += [
                en.get("entropia_actual", 0.5),
                en.get("entropia_baseline", 0.5),
                en.get("anomalias", 0) / 10.0,
                en.get("shield_activo", 0),
                en.get("dns_tunnels", 0) / 5.0,
                en.get("io_noise", 0) / 100.0,
            ]

            # Cortex (4 features)
            f += [
                cx.get("ciclos_sin_cambios", 0) / 10.0,
                cx.get("max_deg", 0.0),
                cx.get("congelados", 0) / 5.0,
                cx.get("descongelando", 0),
            ]

            # Protocolo Paz (4 features)
            f += [
                pz.get("agentes", 0) / 10.0,
                pz.get("mensajes", 0) / 50.0,
                pz.get("conflictos", 0) / 10.0,
                pz.get("acuerdos", 0) / 20.0,
            ]

            # Memoria Episodica (4 features)
            f += [
                me.get("recuerdos", 0) / 100.0,
                me.get("recuerdos_validos", 0) / 100.0,
                me.get("contaminados", 0) / 20.0,
                me.get("tasa_implantacion", 0.5),
            ]

            # Padding a 68 features si es necesario
            while len(f) < 68:
                f.append(0.0)

            return f[:68]

        except Exception as e:
            LOG.error("World Model: error extrayendo features — %s", e)
            return None

    def predecir(self, features: list) -> dict:
        """Predice salidas de todos los núcleos."""
        if not self.disponible:
            return {}

        import numpy as np
        x = self._scaler.transform(np.array([features[:68]], dtype=np.float32))
        resultado = {}

        for i, nombre in enumerate(TARGETS):
            pred = self._modelos[i].predict(x)[0]
            if nombre == "pi_tipo":
                resultado[nombre] = TIPOS_ATAQUE.get(int(pred), "desconocido")
            elif nombre == "pi_accion":
                resultado[nombre] = ACCIONES.get(int(pred), "monitorear")
            elif nombre == "pi_severidad":
                resultado["pi_severidad_num"] = float(pred)
                if pred < 0.3: resultado[nombre] = "baja"
                elif pred < 0.6: resultado[nombre] = "media"
                else: resultado[nombre] = "alta"
            elif nombre == "cl_loop":
                resultado[nombre] = bool(pred)
            elif nombre == "cx_congelar":
                resultado[nombre] = bool(pred)
            elif nombre == "cd_necesita":
                resultado[nombre] = bool(pred > 0.5)
            elif nombre == "ij_aceptable":
                resultado[nombre] = bool(pred)
            elif nombre == "en_anomalia":
                resultado[nombre] = bool(pred)
            else:
                resultado[nombre] = float(pred) if isinstance(pred, (float, np.floating)) else int(pred)

        return resultado


# Instancia global para acceso rapido
_modelo_global: Optional[WorldModel] = None


def obtener_modelo() -> WorldModel:
    """Singleton del World Model."""
    global _modelo_global
    if _modelo_global is None:
        _modelo_global = WorldModel()
    return _modelo_global
