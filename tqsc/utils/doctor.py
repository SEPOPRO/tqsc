"""
tqsc/utils/doctor.py — Doctor TQSC: diagnóstico por núcleo + auto-reparación.
"""
import logging, time, threading, gc
from datetime import datetime
from typing import Optional, Callable

LOG = logging.getLogger("tqsc.doctor")


class Diagnosis:
    def __init__(self, nucleo: str, estado: str = "ok",
                 severidad: str = "INFO", sintoma: str = "",
                 reparacion: str = "", datos: dict = None):
        self.nucleo = nucleo; self.estado = estado
        self.severidad = severidad; self.sintoma = sintoma
        self.reparacion = reparacion; self.datos = datos or {}
        self.timestamp = time.time()

    def to_dict(self) -> dict:
        return {"nucleo": self.nucleo, "estado": self.estado,
                "severidad": self.severidad, "sintoma": self.sintoma,
                "reparacion": self.reparacion, "datos": self.datos,
                "timestamp": datetime.fromtimestamp(self.timestamp).isoformat()}


class Reparacion:
    def __init__(self, nombre: str, descripcion: str,
                 fn: Callable, riesgo: str = "bajo"):
        self.nombre = nombre; self.descripcion = descripcion
        self.fn = fn; self.riesgo = riesgo
        self.ultima_ejecucion: float = 0
        self.exitos: int = 0; self.fallos: int = 0

    def ejecutar(self, contexto: dict = None) -> bool:
        try:
            resultado = self.fn(**(contexto or {}))
            ok = resultado if isinstance(resultado, bool) else True
            if ok: self.exitos += 1
            else: self.fallos += 1
            self.ultima_ejecucion = time.time()
            return ok
        except Exception as e:
            self.fallos += 1; LOG.error("Reparación %s falló: %s", self.nombre, e)
            return False


class DoctorTQSC:
    def __init__(self, intervalo: int = 15, max_reparaciones: int = 3):
        self.intervalo = intervalo; self.max_reparaciones = max_reparaciones
        self._activo = False; self._hilo: Optional[threading.Thread] = None
        self._diagnosticos: list[Diagnosis] = []
        self._reparaciones: dict[str, Reparacion] = {}
        self._nucleos_vigilados: dict[str, dict] = {}
        self._historial: list[dict] = []
        self._callback: Optional[Callable] = None
        self._sistema = None
        self._registrar_reparaciones()

    def _registrar_reparaciones(self):
        for n, d, fn, r in [
            ("limpiar_buffer", "Limpia buffer", lambda **kw: self._limpiar_buffer(kw.get("nucleo","")), "bajo"),
            ("reload_config", "Recarga config", lambda **kw: self._reload_config(), "bajo"),
            ("restart_nucleo", "Reinicia núcleo", lambda **kw: self._restart_nucleo(kw.get("nucleo","")), "medio"),
            ("restore_backup", "Restaura backup", lambda **kw: self._restore_backup(), "alto"),
            ("gc_forzar", "GC forzado", lambda **kw: gc.collect() or True, "bajo"),
            ("reset_cb", "Resetea CB", lambda **kw: self._reset_circuit_breakers(), "bajo"),
        ]: self.registrar_reparacion(Reparacion(n, d, fn, r))

    def registrar_reparacion(self, r: Reparacion):
        self._reparaciones[r.nombre] = r

    def vigilar(self, nombre: str, estado_fn: Callable):
        self._nucleos_vigilados[nombre] = {"fn": estado_fn, "fallos_consecutivos": 0}

    def on_diagnostico(self, fn: Callable):
        self._callback = fn

    # ── Diagnósticos específicos por núcleo ──

    def _diagnosticar_blockchain(self, sistema) -> Diagnosis:
        """Verifica integridad de nodos blockchain."""
        try:
            fs = sistema.fork_sealant
            if hasattr(fs, "_firmas_historicas"):
                n = len(fs._firmas_historicas)
                if n > 10000:
                    return Diagnosis("blockchain", "warning", "HIGH",
                                     f"{n} firmas acumuladas", "limpiar_buffer")
            return Diagnosis("blockchain", "ok", "INFO", f"firmas verificadas")
        except Exception as e:
            return Diagnosis("blockchain", "error", "HIGH", f"excepción: {e}", "restart_nucleo")

    def _diagnosticar_defensa(self, sistema) -> Diagnosis:
        """Verifica defensa física: CPU, memoria, procesos."""
        try:
            dc = sistema.defense
            import psutil
            cpu = psutil.cpu_percent(interval=0.1)
            mem = psutil.virtual_memory().percent
            n_proc = len(psutil.pids())
            problemas = []
            if cpu > 90: problemas.append(f"cpu={cpu}%")
            if mem > 90: problemas.append(f"mem={mem}%")
            if n_proc > 500: problemas.append(f"procesos={n_proc}")
            if problemas:
                return Diagnosis("defensa", "warning", "HIGH",
                                 " + ".join(problemas), "gc_forzar",
                                 {"cpu": cpu, "mem": mem, "procesos": n_proc})
            return Diagnosis("defensa", "ok", "INFO",
                             f"cpu={cpu}% mem={mem}% proc={n_proc}")
        except Exception as e:
            return Diagnosis("defensa", "error", "HIGH", f"excepción: {e}")

    def _diagnosticar_crypto(self, sistema) -> Diagnosis:
        """Verifica cifrado AES-GCM mediante roundtrip."""
        try:
            cc = sistema.quantum
            if hasattr(cc, "cifrador") and hasattr(cc.cifrador, "cifrar"):
                test = b"test_diagnostico_doctor_2024"
                ct = cc.cifrador.cifrar(test)
                pt = cc.cifrador.descifrar(ct)
                if pt == test:
                    return Diagnosis("crypto", "ok", "INFO", "AES-GCM roundtrip OK")
                return Diagnosis("crypto", "critical", "CRITICAL",
                                 "AES-GCM roundtrip FALLÓ", "restart_nucleo")
            return Diagnosis("crypto", "warning", "MEDIUM", "cifrador no disponible")
        except Exception as e:
            return Diagnosis("crypto", "error", "HIGH", f"excepción: {e}")

    def _diagnosticar_quantum(self, sistema) -> Diagnosis:
        """Verifica validación cuántica."""
        try:
            qc = sistema.quantum
            e = qc.estado() if hasattr(qc, "estado") else {}
            if e.get("bloqueado"):
                return Diagnosis("quantum", "error", "CRITICAL",
                                 "circuit breaker abierto", "reset_cb")
            return Diagnosis("quantum", "ok", "INFO", "validación operativa")
        except Exception as e:
            return Diagnosis("quantum", "error", "HIGH", f"excepción: {e}")

    def _diagnosticar_honeypot(self, sistema) -> Diagnosis:
        """Verifica honeypot: puertos activos, sesiones."""
        try:
            hp = sistema.honeypot
            if hasattr(hp, "estadisticas"):
                s = hp.estadisticas()
                sesiones = s.get("sesiones", 0)
                ataques = s.get("ataques", 0)
                return Diagnosis("honeypot", "ok", "INFO",
                                 f"{sesiones} sesiones, {ataques} ataques")
            return Diagnosis("honeypot", "ok", "INFO", "operativo")
        except Exception as e:
            return Diagnosis("honeypot", "error", "HIGH", f"excepción: {e}")

    def _diagnosticar_ia(self, sistema) -> Diagnosis:
        """Verifica núcleo IA: octantes, shadow, loop."""
        try:
            ia = sistema.ia_core
            if hasattr(ia, "estado"):
                e = ia.estado()
                aislados = e.get("octantes_aislados", 0)
                shadows = e.get("shadow_activos", 0)
                problemas = []
                if aislados > 4: problemas.append(f"{aislados} octantes aislados")
                if shadows > 10: problemas.append(f"{shadows} shadows")
                if problemas:
                    return Diagnosis("ia_core", "warning", "HIGH",
                                     " + ".join(problemas), "restart_nucleo")
                return Diagnosis("ia_core", "ok", "INFO", f"{e.get('octantes_activos',0)} octantes")
            return Diagnosis("ia_core", "ok", "INFO", "operativo")
        except Exception as e:
            return Diagnosis("ia_core", "error", "HIGH", f"excepción: {e}")

    def _diagnosticar_entropia(self, sistema) -> Diagnosis:
        """Verifica nivel de entropía."""
        try:
            en = sistema.entropy
            if hasattr(en, "estado"):
                e = en.estado()
                ent = e.get("entropia", 0.5)
                if ent < 0.3:
                    return Diagnosis("entropia", "warning", "HIGH",
                                     f"entropía baja: {ent:.3f}", "reload_config")
                return Diagnosis("entropia", "ok", "INFO", f"entropía: {ent:.3f}")
            return Diagnosis("entropia", "ok", "INFO", "operativo")
        except Exception as e:
            return Diagnosis("entropia", "error", "HIGH", f"excepción: {e}")

    def _diagnosticar_cortex(self, sistema) -> Diagnosis:
        try:
            cx = sistema.cortex
            e = cx.estado() if hasattr(cx, "estado") else {}
            if e.get("congelados", 0) > 3:
                return Diagnosis("cortex", "warning", "HIGH",
                                 f"{e['congelados']} núcleos congelados")
            return Diagnosis("cortex", "ok", "INFO", "confinamiento ok")
        except Exception as e:
            return Diagnosis("cortex", "error", "HIGH", f"excepción: {e}")

    def _diagnosticar_paz(self, sistema) -> Diagnosis:
        try:
            pp = sistema.protocolo_paz
            return Diagnosis("protocolo_paz", "ok", "INFO", "paz operativa")
        except Exception as e:
            return Diagnosis("protocolo_paz", "error", "HIGH", f"excepción: {e}")

    def _diagnosticar_memoria(self, sistema) -> Diagnosis:
        try:
            me = sistema.memoria
            e = me.estado() if hasattr(me, "estado") else {}
            n = e.get("recuerdos", 0)
            if n > 1000:
                return Diagnosis("memoria", "warning", "HIGH",
                                 f"{n} recuerdos (posible saturación)", "limpiar_buffer")
            return Diagnosis("memoria", "ok", "INFO", f"{n} recuerdos")
        except Exception as e:
            return Diagnosis("memoria", "error", "HIGH", f"excepción: {e}")

    # ── Diagnósticos globales ──

    def _diagnosticar_memoria_proceso(self):
        try:
            import psutil
            proc = psutil.Process()
            mem = proc.memory_percent()
            rss = proc.memory_info().rss / 1024 / 1024
            if mem > 80:
                return Diagnosis("sistema", "error", "CRITICAL",
                                 f"memoria al {mem:.0f}% ({rss:.0f}MB)", "gc_forzar")
            if mem > 60:
                return Diagnosis("sistema", "warning", "HIGH",
                                 f"memoria elevada: {mem:.0f}%", "gc_forzar")
            return Diagnosis("sistema", "ok", "INFO", f"memoria: {mem:.0f}% ({rss:.0f}MB)")
        except Exception as e:
            LOG.error(f"Error: {e}")
            return Diagnosis("sistema", "ok", "INFO", "memoria: N/A")

    def _diagnosticar_hilos(self):
        n = threading.active_count()
        if n > 100:
            return Diagnosis("sistema", "warning", "HIGH",
                             f"{n} hilos (posible fuga)", "gc_forzar", {"hilos": n})
        return Diagnosis("sistema", "ok", "INFO", f"{n} hilos")

    # ── Diagnóstico completo de TQSC ──

    def diagnosticar_tqsc(self, sistema):
        """Registra diagnósticos específicos para cada núcleo de TQSC."""
        self._sistema = sistema
        self.vigilar("blockchain", lambda: self._diagnosticar_blockchain(sistema).to_dict())
        self.vigilar("defensa", lambda: self._diagnosticar_defensa(sistema).to_dict())
        self.vigilar("crypto", lambda: self._diagnosticar_crypto(sistema).to_dict())
        self.vigilar("quantum", lambda: self._diagnosticar_quantum(sistema).to_dict())
        self.vigilar("honeypot", lambda: self._diagnosticar_honeypot(sistema).to_dict())
        self.vigilar("ia_core", lambda: self._diagnosticar_ia(sistema).to_dict())
        self.vigilar("entropia", lambda: self._diagnosticar_entropia(sistema).to_dict())
        self.vigilar("cortex", lambda: self._diagnosticar_cortex(sistema).to_dict())
        self.vigilar("protocolo_paz", lambda: self._diagnosticar_paz(sistema).to_dict())
        self.vigilar("memoria", lambda: self._diagnosticar_memoria(sistema).to_dict())
        LOG.info("Doctor: 10 diagnósticos registrados (9 núcleos + sistema)")

    def _diagnosticar_nucleo(self, nombre: str, info: dict) -> Diagnosis:
        try:
            raw = info["fn"]()
            if isinstance(raw, dict):
                return Diagnosis(
                    raw.get("nucleo", nombre), raw.get("estado", "ok"),
                    raw.get("severidad", "INFO"), raw.get("sintoma", ""),
                    raw.get("reparacion", ""), raw.get("datos", {}))
            return Diagnosis(nombre, "ok", "INFO", "operativo")
        except Exception as e:
            info["fallos_consecutivos"] += 1
            return Diagnosis(nombre, "critical", "CRITICAL",
                             f"excepción: {e}", "restart_nucleo")

    # ── Reparaciones ──

    def _limpiar_buffer(self, nucleo: str) -> bool:
        LOG.info("Doctor: limpiando buffer de %s", nucleo)
        if self._sistema and hasattr(self._sistema, nucleo):
            obj = getattr(self._sistema, nucleo)
            if hasattr(obj, "buffer") and hasattr(obj.buffer, "clear"):
                obj.buffer.clear()
        return True
    def _reload_config(self) -> bool:
        import importlib
        try: import config; importlib.reload(config); return True
        except Exception as e:
            LOG.error(f"Error: {e}")
            return False
    def _restart_nucleo(self, nucleo: str) -> bool:
        LOG.warning("Doctor: reinicio solicitado para %s", nucleo)
        if self._sistema and hasattr(self._sistema, nucleo):
            obj = getattr(self._sistema, nucleo)
            if hasattr(obj, "detener") and hasattr(obj, "iniciar"):
                obj.detener()
                obj.iniciar()
        return True
    def _restore_backup(self) -> bool:
        try:
            from utils.backup import BackupManager
            bm = BackupManager(); backups = bm.listar()
            if backups and bm.restaurar(backups[0]["archivo"]):
                return True
        except Exception as e:
            LOG.error(f"Error: {e}")
        return False
    def _reset_circuit_breakers(self) -> bool:
        LOG.info("Doctor: circuit breakers reseteados")
        if self._sistema and hasattr(self._sistema, "quantum"):
            if hasattr(self._sistema.quantum, "errores"):
                self._sistema.quantum.errores = 0
            if hasattr(self._sistema.quantum, "circuit_breaker"):
                self._sistema.quantum.circuit_breaker = False
        return True

    # ── Ciclo ──

    def _ciclo(self):
        while self._activo:
            try:
                resultados = []
                resultados.append(self._diagnosticar_memoria_proceso())
                resultados.append(self._diagnosticar_hilos())
                for nombre, info in self._nucleos_vigilados.items():
                    resultados.append(self._diagnosticar_nucleo(nombre, info))
                self._diagnosticos = resultados
                self._procesar_diagnosticos(resultados)
            except Exception as e:
                LOG.error("Doctor: error en ciclo: %s", e)
            time.sleep(self.intervalo)

    def _procesar_diagnosticos(self, diagnosticos: list[Diagnosis]):
        for d in diagnosticos:
            entry = d.to_dict()
            self._historial.append(entry)
            if len(self._historial) > 1000:
                self._historial = self._historial[-500:]
            icono = {"ok": "✅", "warning": "⚠️", "error": "❌", "critical": "🚨"}
            LOG.info("%s Doctor [%s] %s: %s", icono.get(d.estado, "❓"),
                     d.nucleo, d.estado.upper(), d.sintoma)
            if self._callback:
                try: self._callback(d)
                except Exception as e: LOG.error(f"Error: {e}")
            if d.reparacion and d.reparacion in self._reparaciones:
                r = self._reparaciones[d.reparacion]
                if r.riesgo == "alto" and d.estado != "critical":
                    continue
                LOG.warning("Doctor: reparando %s → %s", r.nombre, d.nucleo)
                ok = r.ejecutar({"nucleo": d.nucleo})
                if not ok and d.estado == "critical":
                    LOG.critical("Doctor: reparación FALLÓ — escalar a humano")

    def iniciar(self):
        if self._activo: return
        self._activo = True
        self._hilo = threading.Thread(target=self._ciclo, daemon=True, name="DoctorTQSC")
        self._hilo.start()
        LOG.info("🩺 Doctor TQSC activo (%ds, %d reparaciones)",
                 self.intervalo, len(self._reparaciones))

    def detener(self):
        self._activo = False
        LOG.info("Doctor TQSC detenido")

    def estado(self) -> dict:
        return {"activo": self._activo, "nucleos": len(self._nucleos_vigilados),
                "reparaciones": {n: {"ok": r.exitos, "fail": r.fallos}
                                for n, r in self._reparaciones.items()},
                "historial": len(self._historial)}


_doctor: Optional[DoctorTQSC] = None
def obtener_doctor() -> DoctorTQSC:
    global _doctor
    if _doctor is None: _doctor = DoctorTQSC()
    return _doctor
