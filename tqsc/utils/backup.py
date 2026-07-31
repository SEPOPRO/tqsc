"""
tqsc/utils/backup.py — Nivel 4: Backup/Restore + state export.
"""
import json, logging, os, time, shutil, hashlib, hmac
from pathlib import Path
from datetime import datetime

LOG = logging.getLogger("tqsc.backup")

class BackupManager:
    """Exporta/importa estado completo del sistema."""

    def __init__(self, data_dir: str = "data", backup_dir: str = "data/backups"):
        self.data_dir = Path(data_dir)
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def listar(self) -> list[dict]:
        backups = []
        for f in sorted(self.backup_dir.glob("*.json"), reverse=True):
            try:
                data = json.loads(f.read_text())
                backups.append({
                    "archivo": f.name, "timestamp": data.get("timestamp", "?"),
                    "tamano": f.stat().st_size, "nucleos": list(data.get("estado", {}).keys()),
                })
            except (json.JSONDecodeError, OSError):
                continue
        return backups

    def crear(self, estado: dict, etiqueta: str = "") -> str:
        try:
            raw = json.dumps(estado, sort_keys=True, ensure_ascii=False, default=str)
        except (TypeError, ValueError) as e:
            LOG.error("Backup: estado no serializable — %s", e)
            return ""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        nombre = f"backup_{timestamp}{'_'+etiqueta if etiqueta else ''}.json"
        ruta = self.backup_dir / nombre
        payload = {
            "timestamp": datetime.now().isoformat(),
            "version": "2.0",
            "etiqueta": etiqueta,
            "estado": estado,
            "checksum": hashlib.sha256(json.dumps(estado, sort_keys=True).encode()).hexdigest()[:32],
        }
        ruta.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
        LOG.info("Backup creado: %s (%d bytes)", nombre, ruta.stat().st_size)
        return nombre

    def restaurar(self, nombre: str) -> dict | None:
        ruta = self.backup_dir / nombre
        # Anti path traversal — verificar sin cambiar la ruta
        try:
            ruta_resuelta = str(ruta.resolve())
            base_resuelta = str(self.backup_dir.resolve())
            if not ruta_resuelta.startswith(base_resuelta):
                LOG.error("Path traversal detectado: %s", nombre)
                return None
        except (ValueError, OSError) as e:
            LOG.error("Error validando ruta: %s", e)
            return None
        if not ruta.exists():
            LOG.error("Backup no encontrado: %s", nombre)
            return None
        try:
            data = json.loads(ruta.read_text())
            checksum = hashlib.sha256(json.dumps(data["estado"], sort_keys=True).encode()).hexdigest()[:32]
            if checksum != data.get("checksum", ""):
                LOG.critical("Backup CORRUPTO: checksum no coincide")
                return None
            LOG.info("Backup restaurado: %s (%s)", nombre, data.get("timestamp", "?"))
            return data["estado"]
        except (json.JSONDecodeError, KeyError) as e:
            LOG.error("Backup inválido: %s", e)
            return None

    def limpiar(self, max_backups: int = 30):
        backups = sorted(self.backup_dir.glob("*.json"))
        while len(backups) > max_backups and backups:
            backups[0].unlink()
            backups = backups[1:]
