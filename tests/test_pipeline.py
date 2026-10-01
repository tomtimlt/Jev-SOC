"""Tests du collecteur, du correlator et du sérialiseur (sans réseau, données inventées)."""

from jevsoc.collector import Alert, clean_text, normalize_wazuh
from jevsoc.correlator import correlate, hub_entities, is_judgeable
from jevsoc.serializer import STATE_VERSION, serialize


def alert(i, minute, rule="100", level=5, host=None, src=None, users=(), detail="", desc="d"):
    return Alert(
        id=str(i),
        ts=1_700_000_000 + minute * 60,
        level=level,
        rule_id=rule,
        description=desc,
        detail=detail,
        host=host,
        src_ip=src,
        users=list(users),
    )


def test_normalize_wazuh_alert():
    raw = {
        "@timestamp": "2022-01-24T04:37:58.000000Z",
        "id": "42",
        "predecoder": {"hostname": "intranet-server"},
        "rule": {
            "level": 3,
            "id": "5402",
            "description": "Successful sudo to ROOT executed.",
            "mitre": {"id": ["T1548.003"]},
        },
        "data": {"srcuser": "jhall", "dstuser": "root", "srcip": "10.0.0.5:4444"},
        "full_log": "Jan 24 04:37:58 intranet-server sudo[123]: jhall : TTY=pts/1 ; USER=root",
    }
    a = normalize_wazuh(raw)
    assert (a.host, a.level, a.rule_id, a.mitre) == ("intranet-server", 3, "5402", ["T1548.003"])
    assert a.users == ["jhall", "root"] and a.src_ip == "10.0.0.5"  # port retiré
    assert a.detail == "jhall : TTY=pts/1 ; USER=root"  # préfixe syslog retiré
    assert "ip:10.0.0.5" in a.entities() and "rule:5402" in a.entities()


def test_clean_text_removes_noise():
    assert clean_text("login ok session=<abc123> pid=99") == "login ok session=<…> pid=<n>"
    assert len(clean_text("x" * 500)) == 160


def test_correlate_links_shared_entities_within_gap():
    alerts = [
        alert(1, 0, host="web", rule="1"),
        alert(2, 10, host="web", src="6.6.6.6", rule="2"),
        alert(3, 30, src="6.6.6.6", rule="3"),  # relié à 2 par l'IP
        alert(4, 200, src="6.6.6.6", rule="4"),  # trop tard (> 60 min) : nouveau cluster
    ]
    clusters = correlate(alerts, max_gap_minutes=60, hub_ratio=1.0)
    assert [[a.id for a in c] for c in clusters] == [["1", "2", "3"], ["4"]]


def test_permanent_entity_is_a_hub_but_a_burst_is_not():
    # "mail" est présent toutes les heures (hub) ; l'attaquant fait une rafale en 1 heure.
    alerts = [alert(i, i * 60, host="mail", rule=f"m{i}") for i in range(20)]
    alerts += [alert(100 + i, 5 * 60 + i / 10, src="6.6.6.6", rule=f"s{i}") for i in range(50)]
    hubs = hub_entities(alerts, hub_ratio=0.2, denylist=set())
    assert "host:mail" in hubs and "ip:6.6.6.6" not in hubs
    burst = [c for c in correlate(alerts, hub_ratio=0.2) if len(c) == 50]
    assert len(burst) == 1


def test_denylist_and_window_split():
    alerts = [alert(i, i * 30, users=["SYSTEM"], rule=f"r{i}") for i in range(4)]
    assert len(correlate(alerts, hub_ratio=1.0, denylist={"system"})) == 4  # SYSTEM ne relie rien
    alerts = [alert(i, i * 30, host="h", rule=f"r{i}") for i in range(10)]  # 270 min de chaîne
    clusters = correlate(alerts, max_gap_minutes=60, window_minutes=120, hub_ratio=1.0)
    # 0..270 min découpé en [0-120] et [150-270]
    assert all(c[-1].ts - c[0].ts <= 120 * 60 for c in clusters) and len(clusters) == 2


def test_is_judgeable():
    assert not is_judgeable([alert(1, 0, host="a")])
    assert is_judgeable([alert(i, i, host="a") for i in range(3)])
    assert is_judgeable([alert(1, 0, host="a"), alert(2, 1, users=["bob"])])


def test_serializer_merges_bursts_and_keeps_rare_signals():
    cluster = [alert(i, 0, rule="31101", level=5, detail=f"GET /page{i}", desc="Web 400") for i in range(500)]
    cluster.append(alert(999, 40, rule="5402", level=3, host="srv", users=["jhall"], desc="sudo to ROOT"))
    state = serialize("c1", cluster, max_entries=30)
    assert state["state_version"] == STATE_VERSION and state["alert_count"] == 501
    descs = [e["desc"] for e in state["timeline"]]
    assert descs == ["Web 400", "sudo to ROOT"]  # 500 variantes fusionnées en une ligne
    assert state["timeline"][0]["count"] == 500 and state["timeline"][0]["variants"] == 500
    assert state["window_minutes"] == 40


def test_serializer_prefers_rare_lines_when_truncating():
    cluster = [alert(i, i, rule=f"r{i}", level=10, desc=f"noisy{i}") for i in range(5) for _ in range(3)]
    cluster.append(alert(99, 50, rule="rare", level=3, desc="rare"))
    state = serialize("c1", sorted(cluster, key=lambda a: a.ts), max_entries=3)
    assert "rare" in [e["desc"] for e in state["timeline"]] and state["omitted_groups"] == 3
