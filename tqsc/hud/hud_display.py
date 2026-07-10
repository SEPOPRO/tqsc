"""TQSC v2.0 — HUD con Chart.js."""
import json,logging,threading,time,os
from http.server import HTTPServer,BaseHTTPRequestHandler
LOG=logging.getLogger("tqsc.hud")
def leer():
    try:
        from utils.event_bus import obtener_estado
        e=obtener_estado();e["ataques_hoy"]=sum(1 for x in e.get("eventos",[])if x.get("t")=="ataque")
        return e
    except:pass
    return{"eventos":[],"nucleos":{},"severidad":"--","ataques_hoy":0,"timestamp":"--:--:--","cpu":0,"ram":0,"entropia":0.5,"sesiones_honeypot":0}

HTML="""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta http-equiv="refresh" content="2">
<title>TQSC v2.0</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0b0e14;color:#c9d1d9;font-family:system-ui,sans-serif;padding:12px;height:100vh;overflow:hidden}
.top{display:flex;align-items:center;gap:12px;margin-bottom:8px}
.top h1{font-size:18px;font-weight:600;color:#f0f6fc}
.top h1 em{font-size:11px;color:#8b949e;font-style:normal;margin-left:6px;font-weight:400}
.badge{font-size:11px;font-weight:700;padding:3px 14px;border-radius:3px;text-transform:uppercase;letter-spacing:1px}
.badge.crit{background:#da3633;color:#fff}.badge.high{background:#d4662e;color:#fff}
.badge.med{background:#d29922;color:#fff}.badge.low{background:#1f6feb;color:#fff}.badge.info{background:#238636;color:#fff}
.stats{display:flex;gap:12px;margin-left:auto}
.stats div{text-align:center;padding:0 8px;border-right:1px solid #21262d22}
.stats div:last-child{border:0}.stats .v{font-size:14px;font-weight:600;color:#f0f6fc}.stats .l{font-size:8px;color:#8b949e;text-transform:uppercase;letter-spacing:1px}
.main{display:grid;grid-template-columns:220px 1fr 260px;gap:8px;height:calc(100vh-60px)}
.panel{background:#0e1219;border:1px solid #1a2130;border-radius:6px;padding:8px;display:flex;flex-direction:column;overflow:hidden}
.panel h3{font-size:9px;color:#8b949e;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:4px;font-weight:600}
.chart-wrap{margin-bottom:4px}
.events{overflow-y:auto}
.ev{display:grid;grid-template-columns:38px 64px 60px 1fr 44px;gap:1px;padding:2px 1px;border-bottom:1px solid #21262d22;font-size:10px;align-items:center}
.ev .t{color:#484f58;font-family:monospace}.ev .n{color:#58a6ff;font-weight:500}.ev .a{font-weight:600}
.ev .d{color:#8b949e;overflow:hidden;text-overflow:ellipsis}
.ev .r{font-size:9px;padding:1px 4px;border-radius:2px;text-align:center;font-weight:500}
.r1{background:#da363322;color:#da3633}.r2{background:#d2992222;color:#d29922}.r3{background:#1f6feb22;color:#58a6ff}
.ev.crit{background:#da363308}.ev.crit .a{color:#da3633}
</style></head><body>
<div class="top">
<h1>TQSC <em>Security Operations Center</em></h1>
<div class="badge info" id="sev">--</div>
<div class="stats" id="st"></div>
</div>
<div class="main">
<div class="panel" id="pnuc"><h3>NUCLEI</h3></div>
<div class="panel"><h3>MONITORING</h3>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:4px;margin-bottom:4px">
<div class="chart-wrap"><canvas id="cpuChart" height="80"></canvas></div>
<div class="chart-wrap"><canvas id="ramChart" height="80"></canvas></div>
</div>
<div class="chart-wrap"><canvas id="typeChart" height="100"></canvas></div>
<div class="events" id="ev"></div>
</div>
<div class="panel"><h3>SYSTEM</h3>
<div class="chart-wrap"><canvas id="gaugeChart" height="180"></canvas></div>
<div style="font-size:10px;color:#8b949e;line-height:1.6" id="sinfo"></div>
</div>
</div>
<script>
var RS={bloquear:'r1','enganar':'r2',monitorear:'r3'};
var SEV={CRITICAL:'crit',HIGH:'high',MEDIUM:'med',LOW:'low',INFORMATIONAL:'info'};
var NAMES=["IA_CORE","DEFENSA","CRYPTO","BLOCKCHAIN","HONEYPOT","ENTROPIA","CORTEX","PAZ","MEMORIA"];
var cpuData=[],ramData=[],cpuch,ramch,typech,gaugech;
function initCharts(){
var o={responsive:true,maintainAspectRatio:false,animation:false,plugins:{legend:{display:false}}};
cpuch=new Chart(document.getElementById('cpuChart'),{type:'line',data:{labels:Array(20).fill(''),datasets:[{data:cpuData,borderColor:'#58a6ff',borderWidth:2,pointRadius:0,tension:0.4,fill:true,backgroundColor:'rgba(88,166,255,0.05)'}]},options:{...o,scales:{x:{display:false},y:{display:false,min:0,max:100}}}});
ramch=new Chart(document.getElementById('ramChart'),{type:'line',data:{labels:Array(20).fill(''),datasets:[{data:ramData,borderColor:'#3fb950',borderWidth:2,pointRadius:0,tension:0.4,fill:true,backgroundColor:'rgba(63,185,80,0.05)'}]},options:{...o,scales:{x:{display:false},y:{display:false,min:0,max:100}}}});
typech=new Chart(document.getElementById('typeChart'),{type:'bar',data:{labels:[],datasets:[{data:[],backgroundColor:'#58a6ff44',borderColor:'#58a6ff',borderWidth:1,borderRadius:2}]},options:{...o,scales:{x:{display:false},y:{display:false}}}});
var gc=document.getElementById('gaugeChart').getContext('2d');gaugech=new Chart(gc,{type:'doughnut',data:{datasets:[{data:[0,100],backgroundColor:['#238636','#21262d'],borderWidth:0}]},options:{cutout:'75%',animation:false,plugins:{legend:{display:false},tooltip:{enabled:false}},events:[]}});
}
function drawGauge(sev){
if(!gaugech)return;
var c={CRITICAL:'#da3633',HIGH:'#d4662e',MEDIUM:'#d29922',LOW:'#1f6feb',INFORMATIONAL:'#238636'};
var v={CRITICAL:95,HIGH:75,MEDIUM:50,LOW:25,INFORMATIONAL:10};
gaugech.data.datasets[0].data=[v[sev]||10,100-(v[sev]||10)];
gaugech.data.datasets[0].backgroundColor=[c[sev]||'#238636','#21262d'];
gaugech.update();
}
function u(){fetch('/api').then(function(r){return r.json();}).then(function(d){
var s=d.severidad||'INFORMATIONAL';
document.getElementById('sev').className='badge '+(SEV[s]||'info');document.getElementById('sev').textContent=s;
var cpu=d.cpu||0,ram=d.ram||0,ent=(d.entropia||0.5);cpuData.push(cpu);ramData.push(ram);
if(cpuData.length>20)cpuData.shift();if(ramData.length>20)ramData.shift();
document.getElementById('st').innerHTML='<div><div class="v">'+d.ataques_hoy+'</div><div class="l">Events</div></div><div><div class="v">'+cpu+'%</div><div class="l">CPU</div></div><div><div class="v">'+ram+'%</div><div class="l">RAM</div></div><div><div class="v">'+(d.sesiones_honeypot||0)+'</div><div class="l">Sess</div></div><div><div class="v">'+d.timestamp+'</div><div class="l">UTC</div></div>';
if(!cpuch)initCharts();
if(cpuch)cpuch.update();if(ramch)ramch.update();
var nd=d.nucleos||{};var nh='<div class="panel" id="pnuc"><h3>NUCLEI</h3>';
for(var i=0;i<NAMES.length;i++){var n=NAMES[i];var info=nd[n.toLowerCase()]||{estado:'standby',ultimo_evento:'',alertas:0};var sc=info.estado==='activo'?'color:#3fb950;font-weight:600':'color:#8b949e';nh+='<div style="display:flex;justify-content:space-between;align-items:center;padding:3px 6px;background:#0d1117;border:1px solid #1a2130;border-radius:4px;margin-bottom:2px;font-size:11px"><span><span style="'+sc+'">'+n+'</span></span>'+(info.alertas>0?'<span style="color:#da3633;font-weight:500">'+info.alertas+'</span>':'<span></span>')+'</div>';}
nh+='</div>';document.getElementById('pnuc').outerHTML=nh;
var ev=d.eventos||[];var eh='';for(var i=0;i<Math.min(ev.length,50);i++){var e=ev[i];var c=e.s==='crit'?'crit':'';eh+='<div class="ev '+c+'"><span class="t">'+e.h+'</span><span class="n">'+(e.n||'?')+'</span><span class="a">'+e.a+'</span><span class="d">'+e.d+'</span><span class="r '+(RS[e.r]||'')+'">'+(e.r||'-')+'</span></div>';}
document.getElementById('ev').innerHTML=eh;
drawGauge(s);
if(typech){var types={};for(var i=0;i<Math.min(ev.length,100);i++){var t=ev[i].a;types[t]=(types[t]||0)+1;}var lbls=Object.keys(types).slice(0,8);typech.data.labels=lbls;typech.data.datasets[0].data=lbls.map(function(k){return types[k];});typech.update();}
document.getElementById('sinfo').innerHTML='ML: <b style="color:#58a6ff">'+(d.modelo_ml||'N/A')+'</b><br>Rust: <b style="color:#3fb950">'+(d.rust||'N/A')+'</b><br>Crypto: <b style="color:#3fb950">'+(d.cifrado||'N/A')+'</b><br>Boot: <b style="color:'+(d.boot==='INTEGRIDAD OK'?'#3fb950':'#da3633')+'">'+(d.boot||'N/A')+'</b><br>Geo: <b style="color:#58a6ff">'+(d.geonoise||'N/A')+'</b>';
});}
u();setInterval(u,2000);
</script></body></html>"""

class HUDHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path=="/":self.send_response(200);self.send_header("Content-Type","text/html; charset=utf-8");self.end_headers();self.wfile.write(HTML.encode())
        elif self.path=="/api":self.send_response(200);self.send_header("Content-Type","application/json");self.end_headers();self.wfile.write(json.dumps(leer()).encode())
        else:self.send_response(404);self.end_headers()
    def log_message(self,fmt,*a): LOG.debug("HUD: %s",fmt%a)

class HUDServer:
    def __init__(self,p=9090): self.p=p
    def iniciar(self):
        self._s=HTTPServer(("0.0.0.0",self.p),HUDHandler)
        threading.Thread(target=self._s.serve_forever,daemon=True).start()
        LOG.info("http://localhost:%d",self.p)
