import json, pathlib

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

def build(name, variant):
    c = CLUSTERS[name]
    tl = []
    for t, host, lvl, mitre, full, blind in c["events"]:
        e = {"t": t, "host": host, "level": lvl, "mitre": mitre,
             "desc": blind if variant == "blind" else full}
        if variant == "no_mitre": del e["mitre"]   # variante sans technique MITRE
        if variant == "no_level": del e["level"]   # variante sans niveau de règle
        tl.append(e)
    state = {"cluster_id": f"{name}-{variant}", "hosts": sorted({e["host"] for e in tl}),
             "users": c["users"], "alert_count": len(tl), "timeline": tl}
    if variant != "no_level":
        state["max_rule_level"] = max(e[2] for e in c["events"])
    return state

out = pathlib.Path("variants"); out.mkdir(exist_ok=True)
for name in CLUSTERS:
    for variant in ("full", "no_mitre", "no_level", "blind"):
        (out / f"{name}__{variant}.json").write_text(json.dumps(build(name, variant), indent=2))
print(sorted(p.name for p in out.iterdir()))
