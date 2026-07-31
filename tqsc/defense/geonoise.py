"""
Generates deterministic pseudo-random coordinates based on WiFi SSID hashes. NOT real geolocation. Coordinates are offsets from a base point (CDMX). Useful as a fingerprinting/entropy source, not for actual positioning.
"""
import subprocess, re, json, time, logging, random, os, hashlib
from typing import Optional
from datetime import datetime

try:
    from geopy.geocoders import Nominatim
    from geopy.extra.rate_limiter import RateLimiter
    HAS_GEO = True
except ImportError:
    HAS_GEO = False

LOG = logging.getLogger("tqsc.geonoise")
TQSC_TEST = os.environ.get("TQSC_TEST_MODE") == "1"


def escanear_wifi() -> list[dict]:
    """Escanea redes WiFi cercanas via netsh (Windows).
    Retorna lista de BSSIDs con SSID y señal.
    En Linux/Mac, retorna vacío.
    """
    if TQSC_TEST:
        return [{"bssid": "00:11:22:33:44:55", "ssid": "TEST_NETWORK", "senal": -45}]
    try:
        if os.name != "nt":
            return []
        r = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode != 0:
            return []
        return _parsear_netsh(r.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def _parsear_netsh(output: str) -> list[dict]:
    """Parsea el output de netsh wlan show networks mode=bssid."""
    redes = []
    bssid_actual = {}
    for line in output.split("\n"):
        line = line.strip()
        if line.startswith("SSID"):
            # Nueva red
            if bssid_actual:
                redes.append(bssid_actual)
            m = re.search(r"SSID\s*\d+\s*:\s*(.+)", line)
            ssid = m.group(1).strip() if m else "Desconocido"
            bssid_actual = {"ssid": ssid, "bssids": []}
        elif "BSSID" in line:
            m = re.search(r"BSSID\s*\d+\s*:\s*([\da-fA-F:]+)", line)
            if m:
                bssid_actual.setdefault("bssids", []).append(m.group(1).upper())
        elif "Señal" in line or "Signal" in line:
            m = re.search(r"(\d+)%", line)
            if m:
                bssid_actual["senal"] = int(m.group(1))
    if bssid_actual:
        redes.append(bssid_actual)
    return redes


def _nominatim_geocode(lat: float, lon: float) -> Optional[dict]:
    """Reverse geocoding con Nominatim (gratis, sin key)."""
    if not HAS_GEO:
        return None
    try:
        geo = Nominatim(user_agent="TQSC_GeoNoiseTracker/2.0")
        geocode = RateLimiter(geo.reverse, min_delay=1.0)
        loc = geocode(f"{lat}, {lon}", language="es", exactly_one=True)
        if loc and loc.raw:
            addr = loc.raw.get("address", {})
            return {
                "calle": addr.get("road") or addr.get("pedestrian") or addr.get("street", ""),
                "numero": addr.get("house_number", ""),
                "ciudad": addr.get("city") or addr.get("town") or addr.get("village") or addr.get("municipality", ""),
                "estado": addr.get("state", ""),
                "pais": addr.get("country", ""),
                "codigo_postal": addr.get("postcode", ""),
                "lat": lat, "lon": lon,
                "precision": "calle",
            }
    except Exception as e:
        LOG.debug("Nominatim falló: %s", e)
    return None


def _localizar_por_wifi() -> Optional[dict]:
    """Localiza usando BSSIDs de redes WiFi visibles. Usa un dummy mock determinista."""
    redes = escanear_wifi()
    if not redes:
        return None

    # Dummy mock logic
    mejor = max(redes, key=lambda r: r.get("senal", 0))
    ventana = int(time.time() / 900)  # 15 minutos
    seed = f"{mejor['ssid']}:{ventana}"
    hash_val = int(hashlib.sha256(seed.encode()).hexdigest()[:8], 16)
    
    lat_base, lon_base = 19.4326, -99.1332  # default CDMX
    lat = lat_base + (hash_val % 100) * 0.0001
    lon = lon_base + ((hash_val // 100) % 100) * 0.0001

    resultado = _nominatim_geocode(lat, lon)
    if resultado:
        resultado["fuente"] = "wifi_osm"
        return resultado

    return {"fuente": "wifi_solo", "lat": round(lat, 6), "lon": round(lon, 6),
            "ciudad": "Desconocida", "precision": "estimada"}


def localizar() -> dict:
    """Obtiene ubicación actual.
    Prioridad: WiFi + OSM → ciudad por sistema → random jitter.
    NOTE: The fallback is locale-hash based, not actual GPS.
    """
    # WiFi + OSM (precisión ~calle)
    loc = _localizar_por_wifi()
    if loc:
        # Anti-fingerprinting: jitter gaussiano
        loc["lat"] += random.gauss(0, 0.0005)
        loc["lon"] += random.gauss(0, 0.0005)
        loc["timestamp"] = datetime.now().isoformat()
        return loc

    # Fallback: ciudad desde configuración regional
    import locale
    try:
        locale.setlocale(locale.LC_ALL, "")
        encoding = locale.getdefaultlocale()[1] or "UTF-8"
        pais = locale.getdefaultlocale()[0] or "es_MX"
        ciudad = pais.split("_")[0].upper()
    except (locale.Error, TypeError, ValueError):
        ciudad = "MX"

    hash_val = int(hashlib.sha256(f"{ciudad}:{int(time.time()/3600)}".encode()).hexdigest()[:8], 16)
    lat = (hash_val % 1000) * 0.001 + 19.0
    lon = ((hash_val // 1000) % 1000) * 0.001 - 100.0

    loc2 = _nominatim_geocode(lat, lon)
    if loc2:
        loc2["fuente"] = "locale_osm"
        loc2["lat"] += random.gauss(0, 0.001)
        loc2["lon"] += random.gauss(0, 0.001)
        loc2["timestamp"] = datetime.now().isoformat()
        return loc2

    return {
        "fuente": "fallback", "lat": round(lat + random.gauss(0, 0.002), 6),
        "lon": round(lon + random.gauss(0, 0.002), 6),
        "ciudad": ciudad, "precision": "ciudad",
        "timestamp": datetime.now().isoformat(),
    }
