"""Tests de la partie Windows : entités Sysmon, conversion pour Wazuh, labellisation APT29."""

import importlib.util
import json
from pathlib import Path

from jevsoc.collector import normalize_wazuh

ROOT = Path(__file__).resolve().parents[1]


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


wazuh_replay = load_script("wazuh_replay")
build_apt29 = load_script("build_apt29_dataset")


def wazuh_windows_alert(description, **eventdata):
    """Alerte telle que Wazuh la produit pour un agent Windows (antislashs doublés)."""
    return {
        "@timestamp": "2020-05-02T03:05:16.623000Z",
        "id": "SCRANTON-1",
        "rule": {"level": 12, "id": "92403", "description": description},
        "predecoder": {"hostname": "SCRANTON"},
        "data": {"win": {"system": {"computer": "SCRANTON.dmevals.local"}, "eventdata": eventdata}},
    }


def test_sysmon_entities_link_process_trees_and_files():
    raw = wazuh_windows_alert(
        "Executable dropped",
        processGuid="{47AB858C-E1E4-5EAC-B803-000000000400}",
        parentProcessGuid="{47AB858C-E14E-5EAC-AC03-000000000400}",
        targetFilename="C:\\\\Users\\\\pbeesly\\\\AppData\\\\Local\\\\Temp\\\\x.dll",
        user="DMEVALS\\\\pbeesly",
    )
    a = normalize_wazuh(raw)
    assert a.processes == ["47ab858c-e14e-5eac-ac03-000000000400", "47ab858c-e1e4-5eac-b803-000000000400"]
    assert a.files == ["c:\\users\\pbeesly\\appdata\\local\\temp\\x.dll"]
    assert a.users == ["pbeesly"]
    assert a.detail == "C:\\Users\\pbeesly\\AppData\\Local\\Temp\\x.dll"  # antislashs dédoublés
    assert "proc:47ab858c-e1e4-5eac-b803-000000000400" in a.entities()


def test_agent_event_uses_single_quoted_xml():
    event = {
        "SourceName": "Microsoft-Windows-Sysmon",
        "EventID": 1,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Hostname": "SCRANTON.dmevals.local",
        "UtcTime": "2020-05-02 02:56:14.894",
        "CommandLine": 'cmd.exe /c "whoami" & echo <ok>',
        "AccountName": "SYSTEM",  # méta NXLog : ignoré
    }
    msg = wazuh_replay.to_agent_event(event)
    xml = msg["Event"]
    assert "Name='Microsoft-Windows-Sysmon'" in xml and "SystemTime='2020-05-02T02:56:14.8940000Z'" in xml
    assert "<Data Name='CommandLine'>cmd.exe /c \"whoami\" &amp; echo &lt;ok&gt;</Data>" in xml
    assert "AccountName" not in xml
    assert '\\"' not in json.dumps(msg["Event"]).replace('\\"whoami\\"', "")  # aucun attribut entre "


def test_apt29_stages_and_benign_exclusions():
    lsass = wazuh_windows_alert(
        "Local Security Authority Subsystem Service (LSASS) process was accessed by "
        "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe"
    )
    assert build_apt29.alert_stages(lsass) == ["credential_access"]
    noise = wazuh_windows_alert(
        "Explorer process was accessed by C:\\\\Windows\\\\System32\\\\RuntimeBroker.exe"
    )
    assert build_apt29.alert_stages(noise) == []
    psscript = wazuh_windows_alert(
        "Executable file dropped in folder commonly used by malware",
        targetFilename="C:\\\\Users\\\\pbeesly\\\\AppData\\\\Local\\\\Temp\\\\__PSScriptPolicyTest_abc.ps1",
    )
    assert build_apt29.alert_stages(psscript) == []
    wmi = wazuh_windows_alert(
        "Windows management instrumentation (WMI) created a powershell process",
        commandLine="powershell -exec bypass -windowstyle hidden -e WwBTAHkAcwB0AGUAbQAuAE4AZQB0",
    )
    assert build_apt29.alert_stages(wmi) == ["execution"]
