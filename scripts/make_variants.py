"""Génère la matrice d'ablation : 3 scénarios x 4 variantes = 12 clusters labellisés.

Scénarios :
  attack       phishing -> PowerShell -> persistance -> dump lsass -> mouvement latéral -> exfiltration
  benign       jumeau bénin (patching SCCM, scan Defender, rétention de logs, sauvegarde Azure)
  adversarial  attaque déguisée en SCCM (mêmes noms, mais incohérences de contexte)

Variantes :
  full      tout le contexte
  no_mitre  sans technique MITRE
  no_level  sans niveau de règle
  blind     descriptions sans indice de contexte (mêmes faits observables)

Sortie : data/ablation/<scenario>__<variante>.json, au format des clusters labellisés lus
par eval/eval.py : {scenario, variant, label, kill_chain_stage, notes, rule_levels, state}.

Usage : python scripts/make_variants.py [--out data/ablation]
"""

import argparse
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
VARIANTS = ("full", "no_mitre", "no_level", "blind")

# fmt: off
# (t, hôte, niveau, mitre, description_complète, description_aveugle)
# description_aveugle = mêmes faits observables, sans aucun indice de contexte
CLUSTERS = {
  "attack": dict(users=["j.martin", "svc_backup"], events=[
    ("+0m",   "WS-FIN-07",   5, "T1566.001", "OUTLOOK.EXE spawned WINWORD.EXE opening attachment Facture_Q3.docm", "OUTLOOK.EXE spawned WINWORD.EXE opening Facture_Q3.docm"),
    ("+1m",   "WS-FIN-07",   6, "T1059.001", "WINWORD.EXE spawned powershell.exe with -EncodedCommand", "WINWORD.EXE spawned powershell.exe"),
    ("+3m",   "WS-FIN-07",   4, "T1053.005", "Scheduled task 'OneDriveSyncCheck' created, runs %APPDATA%\\upd.ps1 at logon", "Scheduled task 'OneDriveSyncCheck' created, runs %APPDATA%\\upd.ps1 at logon"),
    ("+47m",  "WS-FIN-07",   7, "T1003.001", "rundll32.exe accessed lsass.exe memory (GrantedAccess 0x1010)", "rundll32.exe accessed lsass.exe memory"),
    ("+52m",  "SRV-FILE-02", 5, "T1021.002", "Network logon (type 3) by svc_backup from WS-FIN-07 to ADMIN$ - first time this pair is seen", "Network logon (type 3) by svc_backup from WS-FIN-07 to ADMIN$"),
    ("+53m",  "SRV-FILE-02", 6, "T1569.002", "New service installed with random name, binary in C:\\Windows\\Temp", "New service installed, binary in C:\\Windows\\Temp"),
    ("+180m", "SRV-FILE-02", 3, "T1560.001", "7z.exe created password-protected archive of D:\\Finance (2.3 GB)", "7z.exe created password-protected archive of D:\\Finance (2.3 GB)"),
    ("+214m", "SRV-FILE-02", 4, "T1567",     "Outbound HTTPS 2.1 GB to cdn-sync-storage[.]top, domain first seen 3 days ago", "Outbound HTTPS 2.1 GB to cdn-sync-storage[.]top"),
  ]),
  "benign": dict(users=["SYSTEM", "svc_sccm"], events=[
    ("+0m",   "WS-FIN-07",   5, "T1059.001", "CcmExec.exe spawned powershell.exe -ExecutionPolicy Bypass -File C:\\Windows\\CCM\\SystemTemp\\patch.ps1", "CcmExec.exe spawned powershell.exe -ExecutionPolicy Bypass -File C:\\Windows\\CCM\\SystemTemp\\patch.ps1"),
    ("+2m",   "WS-FIN-07",   4, "T1053.005", "Scheduled task 'Microsoft\\Configuration Manager\\Patch Reboot' created by SYSTEM", "Scheduled task 'Microsoft\\Configuration Manager\\Patch Reboot' created by SYSTEM"),
    ("+4m",   "WS-FIN-07",   6, "T1569.002", "Service 'CmRcService' reinstalled from C:\\Windows\\CCM", "Service 'CmRcService' reinstalled from C:\\Windows\\CCM"),
    ("+20m",  "WS-FIN-07",   7, "T1003.001", "MsMpEng.exe accessed lsass.exe memory during scheduled scan", "MsMpEng.exe accessed lsass.exe memory"),
    ("+60m",  "SRV-FILE-02", 5, "T1021.002", "Network logon (type 3) by svc_sccm to ADMIN$ from SCCM distribution point, recurring weekly", "Network logon (type 3) by svc_sccm to ADMIN$"),
    ("+62m",  "SRV-FILE-02", 6, "T1569.002", "Service installed: CCMSetup, signed Microsoft binary", "Service installed: CCMSetup"),
    ("+150m", "SRV-FILE-02", 3, "T1560.001", "7z.exe archived D:\\Logs\\IIS older than 30 days (nightly retention job)", "7z.exe archived D:\\Logs\\IIS"),
    ("+190m", "SRV-FILE-02", 4, "T1567",     "Outbound HTTPS 1.8 GB to the organization's Azure Blob backup storage account", "Outbound HTTPS 1.8 GB to an external storage endpoint"),
  ]),
  "adversarial": dict(users=["svc_sccm"], events=[
    ("+0m",   "WS-HR-03",  4, "T1047",     "WmiPrvSE.exe spawned powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\Public\\patch.ps1", "WmiPrvSE.exe spawned powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\Public\\patch.ps1"),
    ("+2m",   "WS-HR-03",  4, "T1053.005", "Scheduled task 'Microsoft\\Configuration Manager\\Patch Reboot' created by svc_sccm, action C:\\Users\\Public\\patch.ps1", "Scheduled task 'Microsoft\\Configuration Manager\\Patch Reboot' created by svc_sccm, action C:\\Users\\Public\\patch.ps1"),
    ("+15m",  "WS-HR-03",  7, "T1003.001", "rundll32.exe accessed lsass.exe memory (GrantedAccess 0x1010)", "rundll32.exe accessed lsass.exe memory"),
    ("+40m",  "SRV-HR-01", 5, "T1021.002", "Network logon (type 3) by svc_sccm from WS-HR-03 to ADMIN$, source is not an SCCM distribution point", "Network logon (type 3) by svc_sccm from WS-HR-03 to ADMIN$"),
    ("+42m",  "SRV-HR-01", 6, "T1569.002", "Service installed: CCMSetup, unsigned binary in C:\\Windows\\Temp", "Service installed: CCMSetup, binary in C:\\Windows\\Temp"),
    ("+120m", "SRV-HR-01", 3, "T1560.001", "7z.exe archived D:\\HR\\Payroll (1.1 GB)", "7z.exe archived D:\\HR\\Payroll (1.1 GB)"),
    ("+170m", "SRV-HR-01", 4, "T1567",     "Outbound HTTPS 1.1 GB to ccmbackup0471.blob.core.windows.net, storage account not in the organization's inventory", "Outbound HTTPS 1.1 GB to ccmbackup0471.blob.core.windows.net"),
  ]),
}

# fmt: on

# Vérité terrain de chaque scénario
LABELS = {
    "attack": dict(
        label="attack",
        kill_chain_stage="exfiltration",
        notes="Chaîne complète phishing -> exfiltration vers un domaine récent",
    ),
    "benign": dict(
        label="benign",
        kill_chain_stage="none_benign",
        notes="Hard negative : mêmes techniques et même niveau max que l'attaque",
    ),
    "adversarial": dict(
        label="attack",
        kill_chain_stage="exfiltration",
        notes="LOTL déguisé en SCCM, exfiltration vers un stockage Azure hors inventaire",
    ),
}


def build(name, variant):
    c = CLUSTERS[name]
    tl = []
    for t, host, lvl, mitre, full, blind in c["events"]:
        e = {
            "t": t,
            "host": host,
            "level": lvl,
            "mitre": mitre,
            "desc": blind if variant == "blind" else full,
        }
        if variant == "no_mitre":
            del e["mitre"]  # variante sans technique MITRE
        if variant == "no_level":
            del e["level"]  # variante sans niveau de règle
        tl.append(e)
    state = {
        "cluster_id": f"{name}-{variant}",
        "hosts": sorted({e["host"] for e in tl}),
        "users": c["users"],
        "alert_count": len(tl),
        "timeline": tl,
    }
    if variant != "no_level":
        state["max_rule_level"] = max(e[2] for e in c["events"])
    return state


def labelled(name, variant):
    """Cluster labellisé : le state envoyé au modèle + la vérité terrain + les niveaux réels.

    `rule_levels` garde les niveaux de règle même en variante no_level : les baselines
    doivent toujours voir les vraies alertes, seule l'entrée du modèle est ablatée.
    """
    return {
        "scenario": name,
        "variant": variant,
        **LABELS[name],
        "rule_levels": [e[2] for e in CLUSTERS[name]["events"]],
        "state": build(name, variant),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default=ROOT / "data" / "ablation", type=pathlib.Path)
    out = parser.parse_args(argv).out
    out.mkdir(parents=True, exist_ok=True)
    for name in CLUSTERS:
        for variant in VARIANTS:
            path = out / f"{name}__{variant}.json"
            path.write_text(
                json.dumps(labelled(name, variant), indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
    print(f"{len(CLUSTERS) * len(VARIANTS)} clusters écrits dans {out}")


if __name__ == "__main__":
    main()
