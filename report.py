"""Weekly customer report, built from the same triage results and health findings the app shows."""
import html
from collections import Counter

from data import CUSTOMER, WEEK


def numbers(results, findings):
    dec = Counter(r["decision"] for r in results)
    sev = Counter(r["severity"] for r in results)
    prod = Counter(r["product"] for r in results)
    return dict(total=len(results), escalate=dec["Escalate"], investigate=dec["Investigate"], close=dec["Close"],
                sev=sev, prod=prod, auto=sum(r["auto"] not in ("None", "Quarantine failed") for r in results),
                devices_flagged=len({f["device"] for f in findings}), findings=len(findings))


def recommendations(results, findings):
    rec = []
    probs = Counter(f["problem"] for f in findings)
    if probs["Unsupported OS"]:
        rec.append(f"Replace or upgrade the {probs['Unsupported OS']} Windows 10 warehouse PCs: they no longer get security updates.")
    if probs["ASR rules only in audit"]:
        rec.append(f"Switch attack surface reduction rules from audit to block on {probs['ASR rules only in audit']} devices.")
    if probs["Tamper protection off"]:
        rec.append("Turn tamper protection back on (1 device); this week someone tried to switch Defender off on another PC.")
    clicks = [r for r in results if r["category"] == "phishing" and r["clicked"]]
    if clicks:
        rec.append(f"Run a short phishing refresher: {len(clicks)} people clicked phishing links this week.")
    if any(r["category"] == "credential theft" for r in results):
        rec.append("Require phishing-resistant MFA for admin accounts after this week's password spray.")
    return rec


def build(results, findings):
    n = numbers(results, findings)
    esc = [r for r in results if r["decision"] == "Escalate"]
    e = html.escape
    rows = "".join(f"<tr><td>{e(r['day'])} {e(r['time'])}</td><td>{e(r['severity'])}</td><td>{e(r['title'])}</td>"
                   f"<td>{e(r['device'] if r['device'] != '-' else r['user'])}</td><td>{e(r['why'] if r['agrees'] else r['rule'])}</td></tr>"
                   for r in esc)
    hrows = "".join(f"<tr><td>{e(f['device'])}</td><td>{e(f['problem'])}</td><td>{e(f['fix'])}</td></tr>" for f in findings)
    recs = "".join(f"<li>{e(x)}</li>" for x in recommendations(results, findings))
    sev = " · ".join(f"{k} {n['sev'].get(k, 0)}" for k in ("High", "Medium", "Low", "Informational"))
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Weekly security report – {e(CUSTOMER)}</title>
<style>html{{background:#fff}}body{{font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#141a22;background:#fff;max-width:860px;margin:0 auto;padding:28px 20px}}
h1{{font-size:24px;margin:0}}h2{{font-size:16px;margin:26px 0 8px;border-bottom:1px solid #d9dee5;padding-bottom:6px}}
.sub{{color:#5a6472}}.k{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:16px 0}}
.k div{{border:1px solid #d9dee5;border-radius:8px;padding:10px 12px}}.k b{{display:block;font-size:24px}}
table{{border-collapse:collapse;width:100%;font-size:13px}}td,th{{border-bottom:1px solid #e6e9ee;padding:6px 8px;text-align:left;vertical-align:top}}
th{{color:#5a6472;font-weight:600}}.note{{color:#5a6472;font-size:12px;margin-top:24px}}</style></head><body>
<h1>Weekly security report</h1><div class="sub">{e(CUSTOMER)} · Managed Endpoint Security · {e(WEEK)}</div>
<div class="k"><div><b>{n['total']}</b>alerts reviewed</div><div><b>{n['escalate']}</b>escalated to L2</div>
<div><b>{n['auto']}</b>stopped automatically</div><div><b>{n['devices_flagged']}</b>devices need attention</div></div>
<p>By severity: {sev}. Decisions: {n['close']} closed, {n['investigate']} investigated, {n['escalate']} escalated.</p>
<h2>Escalated incidents</h2><table><tr><th>When</th><th>Severity</th><th>Alert</th><th>Device / user</th><th>Why</th></tr>{rows}</table>
<h2>Device health</h2><table><tr><th>Device</th><th>Problem</th><th>Fix</th></tr>{hrows}</table>
<h2>Recommendations</h2><ol>{recs}</ol>
<p class="note">Demo report. The company, people, devices and alerts are invented.</p></body></html>"""
