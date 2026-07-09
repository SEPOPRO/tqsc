"""
Tests: GeoNoiseTracker v2 REAL — WiFi + OSM
"""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tqsc"))
os.environ["TQSC_TEST_MODE"] = "1"


def test_escanear_wifi_test_mode():
    from defense.geonoise import escanear_wifi
    redes = escanear_wifi()
    assert len(redes) >= 1
    assert redes[0]["bssid"] == "00:11:22:33:44:55"
    assert redes[0]["ssid"] == "TEST_NETWORK"
    print("✅ WiFi: escaneo en test mode OK")


def test_parsear_netsh():
    from defense.geonoise import _parsear_netsh
    output = """SSID 1 : MI_WIFI
    BSSID 1 : aa:bb:cc:dd:ee:ff
       Señal : 80%
    SSID 2 : VECINO
    BSSID 1 : 11:22:33:44:55:66
       Señal : 40%
"""
    redes = _parsear_netsh(output)
    assert len(redes) == 2
    assert redes[0]["ssid"] == "MI_WIFI"
    assert "AA:BB:CC:DD:EE:FF" in redes[0]["bssids"]
    assert redes[0]["senal"] == 80
    print("✅ netsh: parseo OK (2 redes, %s, señal %d%%)" % (redes[0]["ssid"], redes[0]["senal"]))


def test_localizar_test_mode():
    from defense.geonoise import localizar
    loc = localizar()
    assert loc is not None
    assert "fuente" in loc
    assert "lat" in loc
    assert "lon" in loc
    assert "timestamp" in loc
    print("✅ localizar: %s → lat=%.4f, lon=%.4f" % (loc.get("fuente", "?"), loc.get("lat", 0), loc.get("lon", 0)))


def test_localizar_determinismo_ventana():
    """Misma ubicación en ventana de 15 min da coordenadas similares."""
    from defense.geonoise import localizar
    loc1 = localizar()
    loc2 = localizar()
    # Diferencias entre llamadas deberían ser pequeñas (solo jitter)
    dlat = abs(loc1["lat"] - loc2["lat"])
    dlon = abs(loc1["lon"] - loc2["lon"])
    assert dlat < 0.01, f"lat demasiado diferente: {dlat}"
    assert dlon < 0.01, f"lon demasiado diferente: {dlon}"
    print("✅ determinismo: dlat=%.6f, dlon=%.6f (misma ventana)" % (dlat, dlon))


if __name__ == "__main__":
    test_escanear_wifi_test_mode()
    test_parsear_netsh()
    test_localizar_test_mode()
    test_localizar_determinismo_ventana()
    print("\n🎯 Todos los tests de GeoNoise v2 REAL pasaron")
