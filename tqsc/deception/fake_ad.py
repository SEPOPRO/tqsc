"""
tqsc/deception/fake_ad.py — Objetos Active Directory senuelo con esquema LDAP.
"""
import logging, secrets, time, os
from datetime import datetime
from typing import Optional

LOG = logging.getLogger("tqsc.deception.fake_ad")

USUARIOS = [
    {"cn": "svc_oracle_sync", "spn": True, "desc": "Legacy Oracle sync"},
    {"cn": "sql_sa_replica", "spn": True, "desc": "SQL Server replication"},
    {"cn": "jenkins_automation", "spn": False, "desc": "Jenkins CI/CD"},
    {"cn": "backup_operator_legacy", "spn": True, "desc": "Legacy backup operator"},
    {"cn": "vpn_radius_svc", "spn": False, "desc": "VPN RADIUS auth"},
]
GRUPOS = ["Domain Admins", "Enterprise Admins", "SQL Server Admins", "Backup Operators"]
COMPUS = ["DC-02", "SQL-CLUSTER-PRD", "FS-PROD-01", "EXCH-MAIL-01"]
DOMINIO_DN = "DC=tqsc,DC=internal"


class FakeActiveDirectory:
    """Genera objetos AD con esquema LDAP real. Exportable a LDIF."""

    def generar(self) -> list[dict]:
        objetos = []
        for u in USUARIOS:
            obj = {"objectClass": ["top", "person", "user"],
                   "cn": u["cn"], "sAMAccountName": u["cn"],
                   "userPrincipalName": f"{u['cn']}@tqsc.internal",
                   "description": u["desc"],
                   "whenCreated": f"2025{secrets.choice(range(1,13)):02d}01",
                   "userAccountControl": "512"}
            if u["spn"]:
                obj["servicePrincipalName"] = [f"MSSQLSvc/sql-{u['cn']}.tqsc.internal:1433"]
            objetos.append(obj)

        for g in GRUPOS:
            objetos.append({"objectClass": ["top", "group"], "cn": g,
                            "sAMAccountName": g.replace(" ", ""),
                            "groupType": str(0x80000002)})

        for c in COMPUS:
            objetos.append({"objectClass": ["top", "computer"], "cn": c,
                            "sAMAccountName": f"{c}$",
                            "operatingSystem": "Windows Server 2025",
                            "dNSHostName": f"{c.lower()}.tqsc.internal"})

        LOG.info("🏛️ Fake AD: %d objetos LDAP", len(objetos))
        return objetos

    def exportar_ldif(self) -> str:
        lineas = []
        objetos = self.generar()
        for obj in objetos:
            dn = f"CN={obj['cn']},{DOMINIO_DN}"
            lineas.append(f"dn: {dn}")
            for k, v in obj.items():
                if k == "cn": continue
                if isinstance(v, list):
                    for item in v: lineas.append(f"{k}: {item}")
                else:
                    lineas.append(f"{k}: {v}")
            lineas.append("")
        return "\n".join(lineas)

    def iniciar(self):
        self.generar()

    def detener(self):
        pass

    def estado(self) -> dict:
        return {"total": len(USUARIOS) + len(GRUPOS) + len(COMPUS)}
