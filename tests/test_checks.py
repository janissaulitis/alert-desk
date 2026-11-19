"""The PASS/FAIL checks from SPEC.md."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import data as D, health as H, phishing as PH, playbook as P, report as R  # noqa: E402

ALL = P.triage(D.ALERTS)


def test_1_no_escalation_missed():
    must = [r for r in ALL if r["severity"] == "High" and r["auto"] not in P.FIXED]
    assert all(r["decision"] == "Escalate" for r in must)
    assert P.score(ALL)["escalations_missed"] == 0


def test_2_playbook_agrees_90pct():
    s = P.score(ALL)
    assert s["agree"] / s["n"] >= 0.9


def test_3_no_phishing_marked_safe():
    s = PH.score(D.EMAILS)
    assert s["phishing_missed"] == 0


def test_4_every_finding_has_device_problem_fix():
    for f in H.run(D.DEVICES):
        assert f["device"] and f["problem"] and f["fix"]
    assert H.score(D.DEVICES)["agree"] == len(D.DEVICES)


def test_5_report_matches_queue():
    f = H.run(D.DEVICES)
    n = R.numbers(ALL, f)
    assert n["escalate"] == sum(r["decision"] == "Escalate" for r in ALL)
    assert n["total"] == len(ALL)
    html = R.build(ALL, f)
    assert f"<b>{n['escalate']}</b>escalated" in html


def test_parse_roundtrip():
    for m in D.EMAILS:
        p = PH.parse_raw(PH.to_raw(m))
        assert p["from_addr"] == m["from_addr"] and p["dmarc"] == m["dmarc"]
        assert len(p["links"]) == len(m["links"]) and p["attachments"] == m["attachments"]
