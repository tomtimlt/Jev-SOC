"""Démo live : rejoue de vraies alertes Wazuh et montre Jev trier en temps réel.

Trois commandes :

  record  rejoue un fichier d'alertes d'un coup (sans attendre), appelle le backend à chaque
          re-décision et enregistre le journal d'événements. C'est le filet de sécurité du jour J :
          la page peut ensuite rejouer ce journal sans réseau ni clé API.

            python scripts/demo.py record --backend jev \\
                --alerts data/raw/apt29/alerts/day1_wazuh.ndjson \\
                --history data/raw/apt29/alerts/day2_wazuh.ndjson --truth apt29 \\
                --out demo/recordings/apt29_day1.json

  serve   sert la page de démo sur http://localhost:8000
            --recording FICHIER   : la page rejoue l'enregistrement (vitesse réglable dans la page)
            --live + --alerts ... : vrai direct, le moteur tourne ici et appelle le backend au fil
                                    de l'eau ; les événements sont poussés au navigateur (SSE)

  build   produit une page HTML autonome (enregistrement embarqué) : s'ouvre sans serveur.

Choix d'architecture : serveur HTTP de la bibliothèque standard + Server-Sent Events. Pas de
dépendance de plus, et la même page sert les deux modes (elle ne fait qu'appliquer des
événements, qu'ils viennent d'un fichier ou du flux live).
"""

from __future__ import annotations

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml

from jevsoc.backends import build_backend
from jevsoc.calibration import load_calibration
from jevsoc.collector import Alert, read_alerts
from jevsoc.config import load_config, resolve
from jevsoc.correlator import hub_entities
from jevsoc.live import LiveEngine

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "demo" / "index.html"
HUB_BUCKET_MINUTES = 3


def truth_ids_apt29(path: Path) -> set[str]:
    """Ids des alertes de l'attaquant selon les indicateurs du plan d'émulation APT29."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("build_apt29", ROOT / "scripts" / "build_apt29_dataset.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    ids = set()
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            raw = json.loads(line)
            if module.alert_stages(raw):
                ids.add(raw["id"])
    return ids


def make_engine(args) -> tuple[LiveEngine, list[Alert], dict]:
    """Prépare le moteur, les alertes triées et les métadonnées affichées par la page."""
    config = load_config()
    corr = config["correlation"]
    deny_yaml = yaml.safe_load(resolve(config, corr["denylist_file"]).read_text(encoding="utf-8")) or {}
    denylist = {str(x).lower() for values in deny_yaml.values() for x in values}
    alerts = sorted(read_alerts(args.alerts), key=lambda a: a.ts)
    # Hubs appris sur l'historique (autre journée), jamais sur le flux qu'on juge.
    history = list(read_alerts(args.history)) if args.history else []
    hubs = (
        hub_entities(history, corr["hub_entity_max_ratio"], denylist, HUB_BUCKET_MINUTES)
        if history
        else set()
    )

    backend = build_backend(config, args.backend)
    calibration = load_calibration(resolve(config, config["calibration_file"]), backend.name)
    truth = truth_ids_apt29(Path(args.alerts)) if args.truth == "apt29" else None
    engine = LiveEngine(
        backend.decide, config["policy"], corr, hubs, calibration, args.min_interval, truth_ids=truth
    )
    meta = {
        "type": "meta",
        "title": args.title,
        "source": args.source,
        "start": alerts[0].ts if alerts else 0,
        "duration": round(alerts[-1].ts - alerts[0].ts, 3) if alerts else 0,
        "alerts_total": len(alerts),
        "backend": backend.name,
        "calibrated": bool(calibration),
        "investigate_min": config["policy"]["sophisticated_low"],
        "contain_min": config["policy"]["sophisticated_high"],
        "truth": truth is not None,
    }
    return engine, alerts, meta


def cmd_record(args) -> None:
    engine, alerts, meta = make_engine(args)
    events = []
    for i, alert in enumerate(alerts, 1):
        events.extend(engine.ingest(alert))
        if i % 500 == 0:
            print(f"  {i}/{len(alerts)} alertes", flush=True)
    events.extend(engine.finish())
    decisions = [e for e in events if e["type"] == "decision"]
    meta["model"] = "jev-1.13.0" if meta["backend"] == "jev" else meta["backend"]
    meta["decisions"] = len(decisions)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps({"meta": meta, "events": events}, ensure_ascii=False, separators=(",", ":"))
    )
    print(
        f"{len(alerts)} alertes, {len(decisions)} décisions sur {len({e['cluster'] for e in decisions})} clusters"
    )
    print(f"Enregistrement : {args.out} ({args.out.stat().st_size // 1024} Ko)")


class LiveFeed:
    """Le moteur tourne dans un fil d'exécution et publie ses événements au rythme du temps simulé."""

    def __init__(self, engine: LiveEngine, alerts: list[Alert], meta: dict, speed: float):
        self.events = [meta]
        self.cond = threading.Condition()
        self.engine, self.alerts, self.speed = engine, alerts, speed

    def publish(self, events: list[dict]) -> None:
        with self.cond:
            self.events.extend(events)
            self.cond.notify_all()

    def run(self) -> None:
        start = time.monotonic()
        t0 = self.alerts[0].ts
        for alert in self.alerts:
            wait = (alert.ts - t0) / self.speed - (time.monotonic() - start)
            if wait > 0:
                time.sleep(wait)
            self.publish(self.engine.ingest(alert))
        self.publish(self.engine.finish() + [{"type": "end"}])


def make_handler(recording: Path | None, feed: LiveFeed | None, standalone_page: str):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # pas de bruit dans le terminal pendant la démo
            pass

        def _send(self, body: bytes, content_type: str) -> None:
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                self._send(standalone_page.encode(), "text/html; charset=utf-8")
            elif self.path == "/config.json":
                self._send(json.dumps({"mode": "live" if feed else "recorded"}).encode(), "application/json")
            elif self.path == "/recording.json" and recording:
                self._send(recording.read_bytes(), "application/json")
            elif self.path == "/stream" and feed:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                sent = 0
                try:
                    while True:
                        with feed.cond:
                            while sent >= len(feed.events):
                                feed.cond.wait(timeout=15)
                                if sent >= len(feed.events):
                                    self.wfile.write(b": ping\n\n")  # garde la connexion ouverte
                                    self.wfile.flush()
                            batch = feed.events[sent:]
                        for event in batch:
                            self.wfile.write(f"data: {json.dumps(event, ensure_ascii=False)}\n\n".encode())
                        self.wfile.flush()
                        sent += len(batch)
                except (BrokenPipeError, ConnectionResetError):
                    return
            else:
                self.send_error(404)

    return Handler


def cmd_serve(args) -> None:
    feed = None
    if args.live:
        engine, alerts, meta = make_engine(args)
        feed = LiveFeed(engine, alerts, meta, args.speed)
        threading.Thread(target=feed.run, daemon=True).start()
        print(f"Mode LIVE : {len(alerts)} alertes rejouées à ×{args.speed:g}, backend {meta['backend']}")
    elif not args.recording:
        raise SystemExit("--recording FICHIER ou --live --alerts FICHIER requis")
    server = ThreadingHTTPServer((args.host, args.port), make_handler(args.recording, feed, PAGE.read_text()))
    print(f"Démo : http://{args.host}:{args.port}  (Ctrl+C pour arrêter)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


def build_standalone(recording: Path) -> str:
    """Page autonome : l'enregistrement est embarqué dans la page (aucun serveur nécessaire)."""
    data = recording.read_text(encoding="utf-8").replace("</", "<\\/")  # sûr dans une balise <script>
    embed = f'<script id="recording" type="application/json">{data}</script>'
    return PAGE.read_text(encoding="utf-8").replace("<!--RECORDING-->", embed)


def cmd_build(args) -> None:
    args.out.write_text(build_standalone(args.recording), encoding="utf-8")
    print(f"Page autonome : {args.out} ({args.out.stat().st_size // 1024} Ko)")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Démo live Jev-SOC")
    sub = parser.add_subparsers(dest="command", required=True)

    def engine_args(p):
        p.add_argument("--alerts", type=Path, required=p.prog.endswith("record"))
        p.add_argument("--history", type=Path, help="alertes d'une autre période, pour apprendre les hubs")
        p.add_argument("--backend", choices=["mock", "jev", "laya"])
        p.add_argument("--truth", choices=["apt29"], help="affiche la vérité terrain (indicateurs APT29)")
        p.add_argument(
            "--min-interval", type=float, default=20, help="secondes simulées entre deux décisions"
        )
        p.add_argument("--title", default="Émulation APT29 (MITRE ATT&CK Evaluations), jour 1")
        p.add_argument(
            "--source", default="Journaux Windows/Sysmon OTRF rejoués dans Wazuh 4.14 : vraies alertes"
        )

    record = sub.add_parser("record", help="enregistre un rejeu complet")
    engine_args(record)
    record.add_argument("--out", type=Path, required=True)
    record.set_defaults(func=cmd_record)

    serve = sub.add_parser("serve", help="sert la page de démo")
    engine_args(serve)
    serve.add_argument("--recording", type=Path)
    serve.add_argument("--live", action="store_true")
    serve.add_argument("--speed", type=float, default=20, help="accélération du temps en mode live")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.set_defaults(func=cmd_serve)

    build = sub.add_parser("build", help="page HTML autonome avec l'enregistrement embarqué")
    build.add_argument("--recording", type=Path, required=True)
    build.add_argument("--out", type=Path, required=True)
    build.set_defaults(func=cmd_build)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
