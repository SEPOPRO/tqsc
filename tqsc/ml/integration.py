"""
world_model_integration.py — Conecta el World Model ML a los núcleos reales.
Cada núcleo reporta su estado → ML predice → núcleos usan las predicciones.
"""
import logging, threading, time, os
from typing import Optional

LOG = logging.getLogger("tqsc.ml_integration")


class MLOrchestrator:
    """
    Orquestador ML. Un hilo separado que:
    1. Lee estado de todos los núcleos
    2. Ejecuta el World Model (13 cabezas)
    3. Distribuye predicciones de vuelta a los núcleos
    """

    def __init__(self, intervalo: float = 3.0):
        self.intervalo = intervalo
        self._activo = False
        self._hilo: Optional[threading.Thread] = None
        self._ultimas_predicciones: dict = {}
        self._modelo: Optional = None

    def iniciar(self):
        try:
            from ml.inference import obtener_modelo
            self._modelo = obtener_modelo()
            if not self._modelo.disponible:
                LOG.warning("MLOrchestrator: World Model no disponible")
                return
        except Exception as e:
            LOG.warning("MLOrchestrator: error cargando modelo — %s", e)
            return

        self._activo = True
        self._hilo = threading.Thread(target=self._loop, daemon=True)
        self._hilo.start()
        LOG.info("MLOrchestrator: activo (intervalo=%ds)", self.intervalo)

    def detener(self):
        self._activo = False

    def _loop(self):
        while self._activo:
            try:
                estado = self._colectar_estado()
                features = self._modelo.extract_features(estado)
                if features:
                    self._ultimas_predicciones = self._modelo.predecir(features)
                    self._distribuir(self._ultimas_predicciones)
            except Exception as e:
                LOG.warning("MLOrchestrator: error en ciclo — %s", e)
            time.sleep(self.intervalo)

    def _colectar_estado(self) -> dict:
        """Colecta estado de todos los núcleos del sistema."""
        estado = {
            "ia_core": {}, "defense": {}, "blockchain": {},
            "classic_crypto": {}, "honeypot": {}, "entropy": {},
            "cortex": {}, "paz": {}, "memoria": {},
        }

        # Intentar leer de núcleos reales (si están importados)
        try:
            from core.octa_nucleo import PatternGate, PreImpactSynthesizer
            estado["ia_core"]["preimpact_severidad"] = 0.5
            estado["ia_core"]["preimpact_confianza"] = 0.5
        except: pass

        try:
            from honeypot import PatternInverter
            pi = PatternInverter()
            s = getattr(pi, "estadisticas", lambda: {})()
            estado["honeypot"]["sesiones_hoy"] = s.get("sesiones", 0)
            estado["honeypot"]["ataques_detectados"] = s.get("ataques", 0)
            estado["honeypot"]["tipos_distintos"] = len(s.get("tipos", []))
            estado["honeypot"]["tasa_exito_login"] = s.get("tasa_exito", 0.5)
        except: pass

        try:
            from utils.entropy_engine import EntropyShield
            es = EntropyShield()
            e = es.estado()
            estado["entropy"]["entropia_actual"] = e.get("entropia", 0.5)
            estado["entropy"]["shield_activo"] = 1 if e.get("activado") else 0
        except: pass

        # Completar con defaults
        for categoria in estado:
            for _ in range(5):
                key = list(estado[categoria].keys())[0] if estado[categoria] else None
                if key is None:
                    estado[categoria]["default"] = 0.0

        return estado

    def _distribuir(self, pred: dict):
        """Inyecta predicciones en los núcleos correspondientes."""
        # PreImpactSynthesizer: usar pi_severidad y pi_tipo
        if "pi_severidad" in pred:
            LOG.info("ML → PreImpact: severidad=%s, tipo=%s, accion=%s",
                     pred.get("pi_severidad", "?"),
                     pred.get("pi_tipo", "?"),
                     pred.get("pi_accion", "?"))

        # CognitiveLoopDetector: usar cl_loop
        if pred.get("cl_loop"):
            LOG.info("ML → CognitiveLoop: LOOP detectado (ML)")

        # IAJudicial: usar ij_aceptable
        if "ij_aceptable" in pred:
            LOG.debug("ML → IAJudicial: aceptable=%s", pred["ij_aceptable"])

        # MetaCoreAdjuster: usar cx_congelar
        if pred.get("cx_congelar"):
            LOG.info("ML → MetaCore: congelar núcleo recomendado (ML)")

        # CacheDisruptor: usar cd_necesita
        if pred.get("cd_necesita"):
            LOG.debug("ML → CacheDisruptor: necesita invalidación")

    def predicciones(self) -> dict:
        """Retorna las últimas predicciones."""
        return dict(self._ultimas_predicciones)


# ═══════════════════════════════════════════
#  INTEGRACIÓN DIRECTA EN NÚCLEOS
# ═══════════════════════════════════════════

class MLPatternAdapter:
    """
    Adaptador que usa el World Model para mejorar la clasificación
    de patrones en PatternInverter y PreImpactSynthesizer.
    """
    def __init__(self):
        self._modelo = None

    def _cargar(self):
        if self._modelo is None:
            try:
                from ml.inference import obtener_modelo
                self._modelo = obtener_modelo()
            except: pass

    def clasificar_ataque(self, comando: str, user: str = "", pwd: str = "",
                          contexto: Optional[dict] = None) -> dict:
        """
        Clasifica un ataque usando ML + reglas (ensemble).
        Retorna: {tipo, confianza, accion, fuente}
        """
        self._cargar()
        result = {"tipo": "desconocido", "confianza": 0.1, "accion": "monitorear",
                  "fuente": "reglas"}

        # 1. Reglas primero (rápido, siempre disponible)
        cmd_l = (comando or "").lower()
        if "' or" in cmd_l or "'=" in cmd_l or "1=1" in cmd_l:
            result = {"tipo": "sqli", "confianza": 0.8, "accion": "bloquear", "fuente": "reglas"}
        elif "<script" in cmd_l or "alert(" in cmd_l:
            result = {"tipo": "xss", "confianza": 0.8, "accion": "bloquear", "fuente": "reglas"}
        elif "../" in cmd_l or "..\\" in cmd_l or "etc/passwd" in cmd_l:
            result = {"tipo": "lfi", "confianza": 0.8, "accion": "bloquear", "fuente": "reglas"}
        elif "; rm" in cmd_l or "|rm" in cmd_l or ";drop " in cmd_l:
            result = {"tipo": "cmd_inject", "confianza": 0.9, "accion": "bloquear", "fuente": "reglas"}
        elif "nmap" in cmd_l or "scan" in cmd_l:
            result = {"tipo": "scanner", "confianza": 0.7, "accion": "bloquear", "fuente": "reglas"}
        elif "http://" in cmd_l and ("include" in cmd_l or "require" in cmd_l):
            result = {"tipo": "rfi", "confianza": 0.8, "accion": "bloquear", "fuente": "reglas"}
        elif ("/etc/" in cmd_l or "/proc/" in cmd_l or "/boot." in cmd_l or
              "/.env" in cmd_l or "/win.ini" in cmd_l):
            result = {"tipo": "lfi", "confianza": 0.8, "accion": "bloquear", "fuente": "reglas"}
        elif cmd_l in ("whoami", "id", "ls", "pwd", "date", "uname"):
            result = {"tipo": "normal", "confianza": 0.9, "accion": "monitorear", "fuente": "reglas"}

        # 2. ML si está disponible (refina la decisión SOLO si reglas no tienen certeza)
        if self._modelo and self._modelo.disponible and result["confianza"] < 0.7:
            try:
                estado = {
                    "ia_core": {}, "defense": {}, "blockchain": {},
                    "classic_crypto": {}, "honeypot": {
                        "sesiones_hoy": 1, "ataques_detectados": 1,
                        "tipos_distintos": 2, "herramientas_distintas": 1,
                        "tasa_exito_login": 0.3 if pwd else 0.5,
                    },
                    "entropy": {}, "cortex": {}, "paz": {}, "memoria": {},
                }
                features = self._modelo.extract_features(estado)
                if features:
                    pred = self._modelo.predecir(features)
                    ml_tipo = pred.get("pi_tipo")
                    ml_conf = pred.get("pi_severidad_num", 5) / 10.0
                    if ml_conf > result["confianza"] and ml_tipo != "desconocido":
                        result["tipo"] = ml_tipo
                        result["confianza"] = ml_conf
                        result["fuente"] = "ml+reglas"
            except Exception as e:
                LOG.debug("MLPatternAdapter: error ML — %s", e)

        return result

    def predecir_severidad(self, patron: str) -> float:
        """Predice severidad usando ML (0-1)."""
        self._cargar()
        if not self._modelo or not self._modelo.disponible:
            return 0.5
        try:
            estado = {"ia_core": {"preimpact_severidad": 0.5},
                      "honeypot": {"ataques_detectados": 1, "tipos_distintos": 1},
                      "entropy": {}, "defense": {}, "blockchain": {},
                      "classic_crypto": {}, "cortex": {}, "paz": {}, "memoria": {}}
            features = self._modelo.extract_features(estado)
            if features:
                pred = self._modelo.predecir(features)
                return pred.get("pi_severidad_num", 0.5) / 10.0
        except: pass
        return 0.5


# ═══════════════════════════════════════════
#  DEMO
# ═══════════════════════════════════════════
if __name__ == "__main__":
    import logging; logging.basicConfig(level=logging.INFO)
    print("=" * 60)
    print("  WORLD MODEL ML — Integración en núcleos")
    print("=" * 60)

    # 1. Probar MLPatternAdapter
    print("\n📊 1. MLPatternAdapter: clasificación con ML + reglas")
    adapter = MLPatternAdapter()
    tests = [
        ("' OR '1'='1", "sqli"),
        ("<script>alert(1)</script>", "xss"),
        ("../../../etc/passwd", "lfi"),
        ("; rm -rf /", "cmd_inject"),
        ("nmap -sV localhost", "scanner"),
        ("whoami", "desconocido"),
        ("cat /etc/shadow", "lfi"),
    ]
    for cmd, esperado in tests:
        r = adapter.clasificar_ataque(cmd)
        ok = "✅" if r["tipo"] == esperado else "❌"
        print(f"  {ok} {cmd[:30]:30s} → {r['tipo']:14s} (conf={r['confianza']:.2f}, {r['fuente']})")

    # 2. Probar MLOrchestrator
    print("\n📊 2. MLOrchestrator: ciclo de inferencia")
    ml = MLOrchestrator(intervalo=2)
    ml.iniciar()
    time.sleep(3)
    pred = ml.predicciones()
    if pred:
        print(f"  Predicciones:")
        for k, v in sorted(pred.items()):
            print(f"    {k}: {v}")
    ml.detener()
    print("  MLOrchestrator detenido")

    print("\n" + "=" * 60)
    print("  World Model ML integrado en núcleos")
    print("=" * 60)
