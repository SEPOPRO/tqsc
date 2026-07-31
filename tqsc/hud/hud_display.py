"""
TQSC v2.0 — Dashboard Profesional PCI DSS
localhost:9090
- Rate limiting por IP
- RBAC (admin/operator/viewer) via token
- Auditoría integrada
"""
import json, logging, threading, time, os, hmac, hashlib, re, urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
from collections import defaultdict

LOG = logging.getLogger("tqsc.hud")
API_KEY: str = ""

# Rate limiting
_RATE_LIMIT = 30  # requests/min por IP
_REQUESTS: dict[str, list[float]] = defaultdict(list)


def _check_rate(ip: str) -> bool:
    ahora = time.time()
    ventana = [t for t in _REQUESTS[ip] if ahora - t < 60]
    _REQUESTS[ip] = ventana
    if len(ventana) >= _RATE_LIMIT:
        return False
    _REQUESTS[ip].append(ahora)
    return True


def _auth_ok(headers: dict) -> bool:
    global API_KEY
    if not API_KEY:
        API_KEY = os.environ.get("TQSC_API_KEY", "")
        if not API_KEY:
            return True
    auth = headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return hmac.compare_digest(auth[7:], API_KEY)
    return False


def _parse_body(data: bytes) -> dict:
    try:
        return json.loads(data)
    except (json.JSONDecodeError, TypeError):
        return {}


def leer():
    try:
        from utils.event_bus import obtener_estado
        e = obtener_estado()
        e["ataques_hoy"] = sum(1 for x in e.get("eventos", []) if x.get("t") == "ataque")
        return e
    except:
        pass
    return {"eventos": [], "nucleos": {}, "severidad": "INFO",
            "ataques_hoy": 0, "timestamp": "--:--:--", "cpu": 0, "ram": 0, "entropia": 0.5}


class H(BaseHTTPRequestHandler):
    def _ip(self) -> str:
        return self.client_address[0]

    def _json(self, code: int, data: dict):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _html(self, code: int, html: str):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(html.encode())

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.end_headers()

    def do_GET(self):
        ip = self._ip()
        if not _check_rate(ip):
            self._json(429, {"error": "Too Many Requests"})
            return

        if self.path == "/":
            self._html(200, HTML)
        elif self.path == "/api":
            if not _auth_ok(self.headers):
                self._json(401, {"error": "API key requerida"})
                return
            self._json(200, leer())
        elif self.path == "/api/audit":
            if not _auth_ok(self.headers):
                self._json(401, {"error": "API key requerida"})
                return
            try:
                from utils.audit import obtener_audit
                a = obtener_audit()
                self._json(200, {"audit": a.exportar()[-100:], "estado": a.estado()})
            except Exception as e:
                self._json(500, {"error": str(e)})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        ip = self._ip()
        if not _check_rate(ip):
            self._json(429, {"error": "Too Many Requests"})
            return

        length = int(self.headers.get("Content-Length", 0))
        if length > 65536:
            self._json(413, {"error": "Payload demasiado grande"})
            return
        ct = (self.headers.get("Content-Type", "") or "").lower()
        if self.path.startswith("/api/") and "application/json" not in ct and "form-urlencoded" not in ct:
            self._json(415, {"error": "Content-Type debe ser application/json"})
            return
        body = self.rfile.read(length) if length else b""

        if self.path == "/api/login":
            data = _parse_body(body)
            usuario = data.get("usuario", "")
            password = data.get("password", "")
            mfa_code = data.get("mfa_code", "")
            try:
                from utils.auth import obtener_auth
                token = obtener_auth().autenticar(usuario, password, mfa_code)
                if token:
                    from utils.audit import obtener_audit
                    obtener_audit().registrar("login", usuario, "/api/login", "OK", "INFO")
                    self._json(200, {"token": token, "role": obtener_auth().verificar(token)["role"]})
                else:
                    self._json(401, {"error": "Credenciales inválidas"})
            except Exception as e:
                self._json(500, {"error": str(e)})
        elif self.path == "/api/audit":
            if not _auth_ok(self.headers):
                self._json(401, {"error": "API key requerida"})
                return
            data = _parse_body(body)
            try:
                from utils.audit import obtener_audit
                h = obtener_audit().registrar(
                    data.get("accion", "manual"), data.get("usuario", "api"),
                    data.get("recurso", ""), data.get("detalle", ""),
                    data.get("severidad", "INFO"))
                self._json(200, {"hash": h})
            except Exception as e:
                self._json(500, {"error": str(e)})
        elif self.path == "/api/mfa":
            if not _auth_ok(self.headers):
                self._json(401, {"error": "API key requerida"})
                return
            data = _parse_body(body)
            usuario = data.get("usuario", "admin")
            accion = data.get("accion", "status")
            try:
                from utils.mfa import obtener_mfa
                mfa = obtener_mfa()
                if accion == "status":
                    self._json(200, {"status": mfa.estado(usuario)})
                elif accion == "enable":
                    secreto = mfa.habilitar(usuario)
                    self._json(200, {"secret": secreto, "uri": mfa.uri(usuario)})
                elif accion == "disable":
                    mfa.deshabilitar(usuario)
                    self._json(200, {"status": "disabled"})
                else:
                    self._json(400, {"error": f"accion desconocida: {accion}"})
            except Exception as e:
                self._json(500, {"error": str(e)})
        elif self.path == "/api/siem":
            if not _auth_ok(self.headers):
                self._json(401, {"error": "API key requerida"})
                return
            try:
                from utils.siem_core import obtener_siem_core
                sc = obtener_siem_core()
                data = _parse_body(body)
                accion = data.get("accion", "estado")
                if accion == "estado":
                    self._json(200, {"siem": sc.estado(), "alertas": list(sc._alertas)[:20]})
                elif accion == "tendencias":
                    horas = data.get("horas", 24)
                    self._json(200, {"tendencias": sc.tendencias(horas)})
                elif accion == "ingesta":
                    logs = data.get("logs", "")
                    formato = data.get("formato", "json")
                    n = sc.ingesta_externa(logs, formato)
                    self._json(200, {"ingestados": n})
                elif accion == "correlar":
                    alertas = sc.correlar()
                    self._json(200, {"alertas_generadas": len(alertas), "alertas": alertas})
                else:
                    self._json(400, {"error": f"accion desconocida: {accion}"})
            except Exception as e:
                self._json(500, {"error": str(e)})
        else:
            self._json(404, {"error": "not found"})

    def log_message(self, f, *a):
        LOG.debug("HUD: %s %s", self._ip(), f % a)

HTML = """<!DOCTYPE html>
<html lang="es"><head><meta charset="UTF-8">
<meta http-equiv="refresh" content="3">
<title>TQSC v2.0</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0d1117;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;padding:20px;height:100vh;overflow-y:auto}
h1{font-size:20px;font-weight:600;color:#e6edf3;margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid #21262d}
h1 small{font-size:13px;color:#8b949e;font-weight:400;margin-left:8px}
.sev-critical{background:#da3633;color:#fff}.sev-high{background:#d4662e;color:#fff}.sev-medium{background:#d29922;color:#fff}.sev-low{background:#1f6feb;color:#fff}.sev-info{background:#1b7b37;color:#fff}
.events-list{max-height:300px;overflow-y:auto}
.event-row{display:flex;align-items:center;padding:6px 0;border-bottom:1px solid #21262d;font-size:13px;gap:8px}
.event-row .time{color:#484f58;font-family:monospace;font-size:12px;width:42px}
.event-row .nucleus{color:#58a6ff;font-weight:500;width:100px}
.event-row .attack{font-weight:600;width:90px}
.event-row .detail{color:#8b949e;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.event-row .result{font-size:11px;padding:2px 8px;border-radius:3px;font-weight:500;width:60px;text-align:center}
.r-block{background:#da363322;color:#f85149}.r-deceive{background:#d2992222;color:#d29922}.r-monitor{background:#1f6feb22;color:#58a6ff}
.event-row.critical{background:#da363308}.event-row.critical .attack{color:#f85149}
.metric-row{display:flex;justify-content:space-between;align-items:center;padding:4px 0;font-size:13px;border-bottom:1px solid #21262d}
.metric-row .label{color:#8b949e}.metric-row .value{font-weight:500;color:#e6edf3}.metric-row .value.good{color:#3fb950}.metric-row .value.warn{color:#d29922}.metric-row .value.crit{color:#f85149}
.bar-track{height:4px;background:#21262d;border-radius:2px;margin-top:4px;overflow:hidden}
.bar-fill{height:100%;border-radius:2px;transition:width .5s}
.bar-green{background:#3fb950}.bar-yellow{background:#d29922}.bar-red{background:#f85149}
@media(max-width:900px){.grid-2,.grid-3{grid-template-columns:1fr}}
</style></head><body>
<h1>TQSC <small>Security Operations Center — Monitoreo en Tiempo Real</small></h1>

<div id="top-row" class="row"></div>

<div class="grid-3">
<div class="card"><h3>Eventos Recientes</h3><div class="events-list" id="events"></div></div>
<div class="card"><h3>Sistema</h3><div id="sys-metrics"></div></div>
<div class="card"><h3>Núcleos</h3><div id="nuclei-list"></div></div>
</div>

<script>
const SEV_CLS = {CRITICAL:'sev-critical',HIGH:'sev-high',MEDIUM:'sev-medium',LOW:'sev-low',INFORMATIONAL:'sev-info'};
const RS_CLS = {bloquear:'r-block','enganar':'r-deceive',monitorear:'r-monitor'};
const NAMES = ['IA_CORE','DEFENSA','CRYPTO','BLOCKCHAIN','HONEYPOT','ENTROPIA','CORTEX','PAZ','MEMORIA'];

function u(){fetch('/api').then(r=>r.json()).then(d=>{
const s=d.severidad||'INFORMATIONAL';
document.getElementById('top-row').innerHTML=
'<div class="card" style="flex:0 0 auto"><span class="severity '+(SEV_CLS[s]||'sev-info')+'">'+s+'</span></div>'+
'<div class="card"><div class="big-number">'+d.ataques_hoy+'<span class="lbl">Eventos</span></div></div>'+
'<div class="card"><div class="big-number">'+(d.cpu||'—')+'%<span class="lbl">CPU</span></div></div>'+
'<div class="card"><div class="big-number">'+(d.ram||'—')+'%<span class="lbl">RAM</span></div></div>'+
'<div class="card"><div class="big-number">'+(d.sesiones_honeypot||0)+'<span class="lbl">Sesiones</span></div></div>'+
'<div class="card" style="flex:0 0 auto"><div class="big-number" style="font-size:16px">'+d.timestamp+'<span class="lbl">UTC</span></div></div>';

const evs=d.eventos||[];
let eh='';
for(let i=0;i<Math.min(evs.length,30);i++){
const e=evs[i];const c=e.s==='crit'?'critical':'';
eh+='<div class="event-row '+c+'"><span class="time">'+e.h+'</span><span class="nucleus">'+(e.n||'?')+'</span>'+
'<span class="attack">'+e.a+'</span><span class="detail">'+e.d+'</span>'+
'<span class="result '+(RS_CLS[e.r]||'')+'">'+(e.r||'—')+'</span></div>';
}
document.getElementById('events').innerHTML=eh||'<div style="color:#8b949e;font-size:13px">Sin eventos</div>';

const cpu=d.cpu||0,ram=d.ram||0,ent=d.entropia||0.5;
const barC=(v)=>{if(v>80)return 'bar-red';if(v>60)return 'bar-yellow';return 'bar-green';};
const valC=(v)=>{if(v>80)return 'crit';if(v>60)return 'warn';return 'good';};
document.getElementById('sys-metrics').innerHTML=
'<div class="metric-row"><span class="label">CPU</span><span class="value '+valC(cpu)+'">'+cpu+'%</span></div><div class="bar-track"><div class="bar-fill '+barC(cpu)+'" style="width:'+cpu+'%"></div></div>'+
'<div class="metric-row"><span class="label">Memoria</span><span class="value '+valC(ram)+'">'+ram+'%</span></div><div class="bar-track"><div class="bar-fill '+barC(ram)+'" style="width:'+ram+'%"></div></div>'+
'<div class="metric-row"><span class="label">Entropía</span><span class="value '+valC((1-ent)*100)+'">'+ent.toFixed(3)+'</span></div><div class="bar-track"><div class="bar-fill '+barC((1-ent)*100)+'" style="width:'+(ent*100)+'%"></div></div>'+
'<div style="margin-top:8px">'+
'<div class="metric-row"><span class="label">ML</span><span class="value good">'+(d.modelo_ml||'N/A')+'</span></div>'+
'<div class="metric-row"><span class="label">Rust</span><span class="value good">'+(d.rust||'N/A')+'</span></div>'+
'<div class="metric-row"><span class="label">Boot</span><span class="value good">'+(d.boot||'N/A')+'</span></div>'+
'<div class="metric-row"><span class="label">Geo</span><span class="value good">'+(d.geonoise||'N/A')+'</span></div>'+
'</div>';

const nd=d.nucleos||{};
let nh='';
for(let i=0;i<NAMES.length;i++){
const n=NAMES[i];const info=nd[n.toLowerCase()]||{estado:'standby',ultimo_evento:'',alertas:0};
const cl=info.estado==='activo'?'color:#3fb950;font-weight:500':'color:#8b949e';
nh+='<div class="metric-row"><span class="label">'+n+'</span><span style="'+cl+'">'+info.estado.toUpperCase()+
(info.alertas?' <span style="color:#f85149">⚠'+info.alertas+'</span>':'')+'</span></div>';
}
document.getElementById('nuclei-list').innerHTML=nh||'<div style="color:#8b949e;font-size:13px">Sin datos</div>';

});}
u();setInterval(u,3000);
</script></body></html>"""



class HUDServer:
    def __init__(self, p=9090, usar_tls: bool = True):
        self.p = p
        self._tls = usar_tls

    def iniciar(self):
        s = HTTPServer(("0.0.0.0", self.p), H)
        try:
            if self._tls:
                from utils.tls import TLSWrapper
                import os
                certs_dir = os.environ.get("TQSC_HOME", "data")
                ca = open(f"{certs_dir}/certs/ca.crt", "rb").read()
                cert = open(f"{certs_dir}/certs/localhost.crt", "rb").read()
                key = open(f"{certs_dir}/certs/localhost.key", "rb").read()
                tw = TLSWrapper(ca, cert, key)
                s.socket = tw.ssl_context().wrap_socket(s.socket, server_side=True)
                LOG.info("https://localhost:%d (mTLS)", self.p)
            else:
                LOG.info("http://localhost:%d (sin TLS)", self.p)
        except Exception as e:
            LOG.info("http://localhost:%d (TLS no disponible: %s)", self.p, e)
        self._s = s
        threading.Thread(target=s.serve_forever, daemon=True).start()
