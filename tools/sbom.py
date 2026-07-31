#!/usr/bin/env python3
"""
SBOM Generator — NIST 800-53 SA-12: Cadena de suministro.
Genera Software Bill of Materials en formato SPDX.
"""
import json, subprocess, sys, os, hashlib
from pathlib import Path
from datetime import datetime


def generar_sbom(ruta_proyecto: str = ".") -> dict:
    base = Path(ruta_proyecto).resolve()

    # Paquetes Python instalados
    paquetes = []
    try:
        r = subprocess.run([sys.executable, "-m", "pip", "list", "--format=json"],
                           capture_output=True, text=True, timeout=30)
        paquetes = json.loads(r.stdout)
    except Exception:
        pass

    # Archivos del proyecto
    archivos = []
    for f in sorted(base.rglob("*.py")):
        if "__pycache__" in str(f) or ".git" in str(f):
            continue
        try:
            archivos.append({
                "path": str(f.relative_to(base)),
                "size": f.stat().st_size,
                "sha256": hashlib.sha256(f.read_bytes()).hexdigest()[:16],
            })
        except (OSError, PermissionError):
            pass

    sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "name": "TQSC v2.0",
        "creationInfo": {
            "created": datetime.utcnow().isoformat() + "Z",
            "creators": [f"Tool: TQSC SBOM Generator"],
        },
        "packages": [
            {
                "name": pkg.get("name", "?"),
                "versionInfo": pkg.get("version", "?"),
                "supplier": "None",
                "SHA256": hashlib.sha256(
                    json.dumps(pkg, sort_keys=True).encode()
                ).hexdigest()[:16],
            }
            for pkg in paquetes
        ],
        "files": archivos,
        "relationships": [
            {"spdxElementId": "TQSC-v2.0", "relationshipType": "DEPENDS_ON",
             "relatedSpdxElement": pkg.get("name", "?")}
            for pkg in paquetes
        ],
    }
    return sbom


def verificar_sbom(sbom_path: str) -> list[str]:
    """Verifica que los archivos listados en el SBOM no hayan cambiado."""
    with open(sbom_path) as f:
        sbom = json.load(f)
    base = Path(sbom.get("_source", "."))
    cambios = []
    for archivo in sbom.get("files", []):
        ruta = base / archivo["path"]
        if not ruta.exists():
            cambios.append(f"{archivo['path']}: eliminado")
            continue
        try:
            sha = hashlib.sha256(ruta.read_bytes()).hexdigest()[:16]
            if sha != archivo["sha256"]:
                cambios.append(f"{archivo['path']}: MODIFICADO (esperado {archivo['sha256']}, actual {sha})")
        except (OSError, PermissionError):
            cambios.append(f"{archivo['path']}: no legible")
    return cambios


if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "."
    sbom = generar_sbom(base)
    sbom["_source"] = base
    sbom_path = os.path.join(base, "sbom.json")
    with open(sbom_path, "w") as f:
        json.dump(sbom, f, indent=2)
    print(f"SBOM: {len(sbom['packages'])} paquetes, {len(sbom['files'])} archivos → {sbom_path}")
