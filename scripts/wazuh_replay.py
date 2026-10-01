"""Fait passer des journaux Windows bruts dans le VRAI moteur de règles Wazuh.

But : obtenir de vraies alertes Wazuh pour des attaques Windows publiques (OTRF / Mordor,
ex. émulation APT29 de MITRE) sans monter de VM Windows. Les règles officielles de Wazuh
décident seules de ce qui devient une alerte : on n'invente aucune alerte.

Fonctionnement :
  1. chaque événement Windows au format NXLog (champs à plat, format des jeux Mordor) est
     reconverti en XML Windows, dans le message qu'un agent Wazuh Windows envoie
     ({"Message": ..., "Event": "<Event>...</Event>"}) ;
  2. il est injecté dans la file d'analyse du gestionnaire (socket queue/sockets/queue), comme
     s'il arrivait d'un agent : c'est le chemin de production, avec le décodeur Windows natif
     windows_eventchannel (wazuh-logtest ne sait pas traiter ce format) ;
  3. les alertes produites sont relues dans logs/alerts/alerts.json, et réécrites en NDJSON
     avec l'heure RÉELLE de l'événement (win.system.systemTime) au lieu de l'heure de rejeu.

Prérequis : wazuh-manager installé et démarré (/var/ossec/bin/wazuh-control start), script
lancé en root. À n'utiliser que sur un gestionnaire de LAB : les événements injectés
produisent de vraies alertes dans ce gestionnaire.

Usage : python scripts/wazuh_replay.py IN.json OUT.ndjson [--rate 3000] [--limit N]
"""

from __future__ import annotations

import argparse
import json
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

OSSEC = Path("/var/ossec")
QUEUE_SOCKET = OSSEC / "queue" / "sockets" / "queue"
ALERTS = OSSEC / "logs" / "alerts" / "alerts.json"
STATE = OSSEC / "var" / "run" / "wazuh-analysisd.state"
EVENTCHANNEL_QUEUE = "f"  # identifiant de file des événements Windows eventchannel dans Wazuh

# Champs NXLog qui décrivent l'événement lui-même (-> win.system) ; les autres méta sont ignorés.
SYSTEM_FIELDS = {
    "SourceName": "providerName",
    "ProviderGuid": "providerGuid",
    "EventID": "eventID",
    "Version": "version",
    "Task": "task",
    "OpcodeValue": "opcode",
    "RecordNumber": "eventRecordID",
    "ExecutionProcessID": "processID",
    "ThreadID": "threadID",
    "Channel": "channel",
    "Hostname": "computer",
}
IGNORED = {
    "EventTime",
    "port",
    "Message",
    "tags",
    "@version",
    "host",
    "Keywords",
    "EventReceivedTime",
    "@timestamp",
    "SeverityValue",
    "Severity",
    "Opcode",
    "EventType",
    "SourceModuleName",
    "SourceModuleType",
    "Category",
    "AccountName",
    "AccountType",
    "Domain",
    "UserID",
    "ActivityID",
}


def event_time(event: dict) -> datetime:
    """Heure réelle de l'événement (UtcTime de Sysmon si présent, sinon @timestamp)."""
    utc = event.get("UtcTime")
    if utc:
        return datetime.strptime(utc[:23], "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(event["@timestamp"].replace("Z", "+00:00"))


def _attr(value) -> str:
    """Attribut XML entre apostrophes, comme dans le XML produit par Windows (EvtRender).

    Important : avec des guillemets doubles, l'encodage JSON les transformerait en \\" et
    l'analyseur XML de Wazuh rejetterait l'événement.
    """
    return "'" + escape(str(value), {"'": "&apos;", '"': "&quot;"}) + "'"


def to_agent_event(event: dict) -> dict:
    """Événement NXLog à plat -> message d'un agent Wazuh Windows : {"Message", "Event": XML}.

    Le décodeur natif windows_eventchannel de Wazuh lit ce XML et produit win.system.* et
    win.eventdata.* (noms de champs Windows avec la première lettre en minuscule).
    """
    when = event_time(event).strftime("%Y-%m-%dT%H:%M:%S.%f0Z")
    system = (
        f"<System><Provider Name={_attr(event.get('SourceName', ''))} Guid={_attr(event.get('ProviderGuid', ''))}/>"
        f"<EventID>{event.get('EventID')}</EventID><Version>{event.get('Version', 0)}</Version>"
        f"<Level>4</Level><Task>{event.get('Task', 0)}</Task><Opcode>{event.get('OpcodeValue', 0)}</Opcode>"
        f"<Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime={_attr(when)}/>"
        f"<EventRecordID>{event.get('RecordNumber', 0)}</EventRecordID><Correlation/>"
        f"<Execution ProcessID={_attr(event.get('ExecutionProcessID', 0))} ThreadID={_attr(event.get('ThreadID', 0))}/>"
        f"<Channel>{escape(str(event.get('Channel', '')))}</Channel>"
        f"<Computer>{escape(str(event.get('Hostname', '')))}</Computer><Security/></System>"
    )
    data = "".join(
        f"<Data Name={_attr(key)}>{escape(str(value))}</Data>"
        for key, value in event.items()
        if key not in SYSTEM_FIELDS and key not in IGNORED and value not in (None, "")
    )
    xml = (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        f"{system}<EventData>{data}</EventData></Event>"
    )
    return {"Message": event.get("Message", ""), "Event": xml}


def analysisd_counter(name: str) -> int:
    for line in STATE.read_text().splitlines():
        if line.startswith(name + "="):
            return int(line.split("=", 1)[1].strip("'"))
    return 0


def inject(src: Path, rate: int, limit: int | None) -> int:
    """Envoie les événements dans la file d'analyse, au plus `rate` événements par seconde."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.connect(str(QUEUE_SOCKET))
    sent, start = 0, time.time()
    with open(src, encoding="utf-8") as handle:
        for line in handle:
            if limit and sent >= limit:
                break
            raw = json.loads(line)
            agent = raw.get("Hostname", "unknown").split(".")[0]
            message = (
                f"{EVENTCHANNEL_QUEUE}:[{abs(hash(agent)) % 900 + 100:03d}] ({agent}) any->EventChannel:"
            )
            sock.send((message + json.dumps(to_agent_event(raw))).encode())
            sent += 1
            ahead = sent / rate - (time.time() - start)
            if ahead > 0:
                time.sleep(ahead)
            if sent % 20000 == 0:
                print(f"  {sent} événements injectés", flush=True)
    sock.close()
    return sent


def collect(offset: int, dst: Path) -> int:
    """Relit les nouvelles alertes Windows et les réécrit avec l'heure réelle de l'événement."""
    count = 0
    with open(ALERTS, encoding="utf-8") as fin, open(dst, "w", encoding="utf-8") as fout:
        fin.seek(offset)
        for line in fin:
            alert = json.loads(line)
            system = ((alert.get("data") or {}).get("win") or {}).get("system")
            if not system or alert.get("location") != "EventChannel":
                continue  # alertes propres au gestionnaire (SCA, FIM...) : pas les nôtres
            alert["@timestamp"] = system["systemTime"]
            alert["id"] = f"{system.get('computer')}-{system.get('eventRecordID')}"
            alert["predecoder"] = {"hostname": system.get("computer", "").split(".")[0]}
            fout.write(json.dumps(alert) + "\n")
            count += 1
    return count


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Rejoue des événements Windows dans un Wazuh de lab")
    parser.add_argument("src", type=Path)
    parser.add_argument("dst", type=Path)
    parser.add_argument("--rate", type=int, default=3000, help="événements par seconde")
    parser.add_argument("--limit", type=int)
    args = parser.parse_args(argv)

    offset = ALERTS.stat().st_size
    received_before = analysisd_counter("events_received")
    dropped_before = analysisd_counter("events_dropped")
    sent = inject(args.src, args.rate, args.limit)
    # Attendre que l'analyse ait tout traité (le fichier d'état est rafraîchi toutes les ~5 s).
    for _ in range(120):
        time.sleep(5)
        if analysisd_counter("events_received") - received_before >= sent:
            break
    time.sleep(5)
    dropped = analysisd_counter("events_dropped") - dropped_before
    alerts = collect(offset, args.dst)
    print(f"{sent} événements injectés, {dropped} perdus par la file, {alerts} alertes Wazuh -> {args.dst}")


if __name__ == "__main__":
    main()
