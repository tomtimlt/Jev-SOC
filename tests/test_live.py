"""Tests du correlator incrémental, du moteur de démo et de la page autonome (sans réseau)."""

import importlib.util
import json
import random
from pathlib import Path

from jevsoc.backends.mock_backend import MockBackend
from jevsoc.collector import Alert
from jevsoc.config import load_config, load_questions
from jevsoc.correlator import IncrementalCorrelator, correlate
from jevsoc.live import LiveEngine

ROOT = Path(__file__).resolve().parents[1]
CONFIG = load_config()


def alert(i, minute, host=None, src=None, rule="r", level=5, users=()):
    return Alert(
        id=str(i),
        ts=1_700_000_000 + minute * 60,
        level=level,
        rule_id=rule,
        description=f"règle {rule}",
        host=host,
        src_ip=src,
        users=list(users),
    )


def partition(clusters):
    return sorted(sorted(a.id for a in c) for c in clusters)


def test_incremental_matches_offline_on_random_streams():
    rng = random.Random(0)
    for _ in range(20):
        alerts = [
            alert(
                i,
                rng.uniform(0, 600),
                host=rng.choice(["a", "b", "c", None]),
                src=rng.choice(["1.1.1.1", "2.2.2.2", None]),
                rule=rng.choice(["r1", "r2", "r3"]),
            )
            for i in range(60)
        ]
        alerts.sort(key=lambda a: a.ts)
        inc = IncrementalCorrelator(
            max_gap_minutes=30, window_minutes=10**6, hubs=set(), max_cluster_size=10**6
        )
        for a in alerts:
            inc.add(a)
        live = [c.alerts for c in inc.clusters.values() if not c.merged_into]
        offline = correlate(alerts, 30, 10**6, hub_ratio=1.0, max_cluster_size=10**6, hubs=set())
        assert partition(live) == partition(offline)


def test_merge_close_and_versions():
    inc = IncrementalCorrelator(max_gap_minutes=60, hubs={"rule:r"})
    c1, _ = inc.add(alert(1, 0, host="web"))
    c2, _ = inc.add(alert(2, 1, src="6.6.6.6"))
    assert c1.id != c2.id
    c3, absorbed = inc.add(alert(3, 2, host="web", src="6.6.6.6"))  # relie les deux
    assert c3.id == c1.id and [c.id for c in absorbed] == [c2.id]
    assert c3.version == 2 and len(c3.alerts) == 3
    assert [c.id for c in inc.close_stale(1_700_000_000 + 200 * 60)] == [c1.id]
    c4, _ = inc.add(alert(4, 201, host="web"))  # cluster fermé : nouvelle histoire
    assert c4.id not in (c1.id, c2.id)


def engine(**kw):
    questions, version = load_questions(ROOT / "config" / "questions.v2.json")
    return LiveEngine(
        MockBackend(questions, version).decide, CONFIG["policy"], CONFIG["correlation"], set(), **kw
    )


def test_engine_redecides_only_when_state_changes():
    eng = engine(min_interval_s=20, truth_ids={"3"})
    events = []
    for i in range(10):  # 10 alertes identiques : même forme de state après la 3e
        events += eng.ingest(alert(i, i * 0.1, host="srv", rule="r1"))
    decisions = [e for e in events if e["type"] == "decision"]
    assert len(decisions) == 1 and decisions[0]["alerts"] == 3 and decisions[0]["version"] == 1
    assert decisions[0]["truth"] is False  # l'alerte "3" n'est pas encore dans le cluster
    events = eng.ingest(alert(99, 2, host="srv", rule="r2"))  # nouvelle ligne de timeline, intervalle écoulé
    decision = [e for e in events if e["type"] == "decision"][0]
    assert decision["version"] == 2 and decision["truth"] is True
    assert {"p", "p_raw", "action", "justification", "mitre", "hosts"} <= decision.keys()


def test_engine_respects_min_interval_then_flushes():
    eng = engine(min_interval_s=60)
    for i in range(3):
        eng.ingest(alert(i, i * 0.01, host="srv", rule="r1"))
    early = eng.ingest(alert(10, 0.5, host="srv", rule="r2"))  # change de forme mais trop tôt
    assert not [e for e in early if e["type"] == "decision"]
    late = eng.ingest(alert(11, 2, host="other", rule="r9"))  # autre cluster ; l'attente est écoulée
    assert [e["cluster"] for e in late if e["type"] == "decision"] == ["clu-0001"]
    final = eng.finish()
    assert all(e["type"] == "close" for e in final)


def test_standalone_page_embeds_recording(tmp_path):
    spec = importlib.util.spec_from_file_location("demo", ROOT / "scripts" / "demo.py")
    demo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(demo)
    rec = tmp_path / "rec.json"
    rec.write_text(json.dumps({"meta": {"type": "meta", "title": "x</script>"}, "events": []}))
    page = demo.build_standalone(rec)
    assert '<script id="recording" type="application/json">' in page
    assert "x<\\/script>" in page and "<!--RECORDING-->" not in page
