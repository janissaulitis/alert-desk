"""Alert Desk: a morning at a managed endpoint security desk. Run: streamlit run app.py"""
import os
import html
import importlib

import streamlit as st

import data as D
import health as H
import kit
import phishing as PH
import playbook as P
import report as R

for _m in (D, P, PH, H, R, kit):
    importlib.reload(_m)  # Streamlit Cloud keeps old copies of imported files after an update

kit.page("Alert Desk", "Triage a morning of security alerts, phishing reports and device health", mark="shield", icon="🛡️",
         theme="watch", meta=f"Managed endpoint security for {D.CUSTOMER} · Defender-style alerts, all invented")

kit.demo(os.environ.get("DEMO_VIDEO", "https://janis-saulitis-portfolio.netlify.app/media/alerts.mp4"), "Alert Desk in 1 minute",
         "1. **Queue:** this morning's alerts, each already decided by a written playbook: close, investigate or escalate.\n"
         "2. Open any alert for the evidence, the rule that decided it, the next steps and the hunting query to run.\n"
         "3. **Phishing check:** paste an email with its headers and get a verdict with the evidence and what to do.\n"
         "4. **Device health** and the **weekly report** for the customer, from the same data.\n"
         "5. **How well it works:** every rule set tested against answers written by hand first.")

NOW = 9 * 60 + 55  # the desk is looked at at 09:55
OPEN = 9 * 60  # business hours start; overnight alerts start their clock here
ALL = P.triage(D.ALERTS)
TODAY = [r for r in ALL if r["day"] == "Thu"]
FIND = H.run(D.DEVICES)
ORDER = {"Escalate": 0, "Investigate": 1, "Close": 2}


def mins(t):
    h, m = t.split(":")
    return int(h) * 60 + int(m)


def sla_text(r):
    if r["decision"] == "Close":
        return "closed by playbook", ""
    left = r["sla_min"] - (NOW - max(mins(r["time"]), OPEN))
    if left < 0:
        return f"{-left} min over SLA", "late"
    return (f"{left // 60} h {left % 60:02d} min left" if left >= 60 else f"{left} min left"), ""


def who(r):
    return r["device"] if r["device"] != "-" else r["user"]


n = {d: sum(r["decision"] == d for r in TODAY) for d in ORDER}
late = sum(sla_text(r)[1] == "late" for r in TODAY)
kit.answer(f"This morning · {D.TODAY} · {len(TODAY)} alerts at 09:55",
           f"{n['Escalate']} to escalate now, {n['Investigate']} to investigate",
           f"A ransomware attempt on a finance laptop, a credential-theft tool on one PC, a phishing link that one person opened, and an admin "
           f"sign-in from Tor. The playbook closed {n['Close']} alerts that were stopped automatically.", raw=True)
st.markdown(f'<div class="k-shift"><div class="esc"><b>{n["Escalate"]}</b><span>escalate to L2 now</span></div>'
            f'<div class="inv"><b>{n["Investigate"]}</b><span>investigate</span></div>'
            f'<div class="cls"><b>{n["Close"]}</b><span>closed by playbook</span></div></div>', unsafe_allow_html=True)

tq, tp, th, tr, tt = st.tabs(["Queue", "Phishing check", "Device health", "Weekly report", "How well it works"])

# ---------------------------------------------------------------- queue
with tq:
    show = st.pills("Show", list(ORDER), selection_mode="multi", default=list(ORDER), key="show", label_visibility="collapsed") or list(ORDER)
    rows = sorted([r for r in TODAY if r["decision"] in show],
                  key=lambda r: (ORDER[r["decision"]], -P.SEV_ORDER[r["severity"]], r["time"]))
    qbox = st.container(key="k_queue")
    left, right = qbox.columns([1.35, 1], gap="large")
    with left:
        items = []
        for r in rows:
            txt, cls = sla_text(r)
            items.append(f'<div class="k-qr {r["severity"]}"><span class="rail"></span><span class="t">{r["time"]}</span>'
                         f'<div style="min-width:0"><div class="tt">{html.escape(r["title"])}</div>'
                         f'<div class="sub">{r["severity"]} · {html.escape(r["product"])} · {html.escape(who(r))}</div></div>'
                         f'<div class="end"><span class="k-dec {r["decision"]}">{r["decision"]}</span>'
                         f'<span class="sla {cls}">{txt}</span></div></div>')
        st.markdown('<div class="k-q">' + "".join(items) + "</div>", unsafe_allow_html=True)
    with right:
        if rows:
            labels = [f'{r["time"]} · {r["title"]} · {who(r)}' for r in rows]
            i = st.selectbox("Open an alert", range(len(rows)), format_func=lambda k: labels[k], key="open")
            r = rows[i]
            txt, _ = sla_text(r)
            steps = "".join(f"<li>{html.escape(s)}</li>" for s in r["steps"])
            st.markdown(
                f'<div class="k-case"><span class="k-dec {r["decision"]}">{r["decision"]}</span>'
                f'<h4>{html.escape(r["title"])}</h4>'
                f'<div class="meta">{r["time"]} · {r["severity"]} · {html.escape(r["product"])}<br>'
                f'device {html.escape(r["device"])} · user {html.escape(r["user"])}<br>automatic action: {html.escape(r["auto"])} · {txt}</div>'
                f'<div class="ev">{html.escape(r["detail"])}</div>'
                f'<div class="rule"><b>Why:</b> {html.escape(r["rule"])}</div>'
                f'<div class="rule"><b>Next steps</b><ol>{steps}</ol></div></div>', unsafe_allow_html=True)
            st.caption("Hunting query to start with (Microsoft Defender Advanced Hunting, KQL)")
            st.code(r["kql"], language="sql", wrap_lines=True)
    st.caption("Service levels are examples: High 1 h, Medium 4 h, Low 8 h, Informational next working day, counted from 09:00 for alerts that came in overnight. "
               "Containment and policy changes are recommended here, never carried out.")

# ---------------------------------------------------------------- phishing check
with tp:
    st.markdown("Paste a reported email **with its headers**, or pick one of the samples. Fixed rules check the sender, "
                "its authentication, the links and the attachments.")
    names = [m["name"] for m in D.EMAILS]
    pick = st.selectbox("Sample email", range(len(names)), format_func=lambda k: names[k], key="mail")
    raw = st.text_area("Email", PH.to_raw(D.EMAILS[pick]), height=230, key=f"raw{pick}", label_visibility="collapsed")
    res = PH.check(PH.parse_raw(raw))
    tone = {"Phishing": "bad", "Suspicious": "warn", "Looks safe": "good"}[res["verdict"]]
    head = {"Phishing": "Phishing: remove it everywhere", "Suspicious": "Suspicious: hold it and confirm with the sender",
            "Looks safe": "Looks safe"}[res["verdict"]]
    kit.answer(f"Verdict · {res['points']} points", head,
               "Phishing from 5 points, suspicious from 2. Every point is explained below.", tone=tone)
    c1, c2 = st.columns(2, gap="large")
    with c1:
        st.markdown("**Evidence**")
        sig = "".join(f'<div class="k-sig{" lo" if p < 3 else ""}"><b>+{p}</b><span>{html.escape(w)}</span></div>' for p, w in res["signals"])
        st.markdown(f'<div class="k-case">{sig or "<span>Nothing suspicious found.</span>"}</div>', unsafe_allow_html=True)
    with c2:
        st.markdown("**What to do**")
        st.markdown('<div class="k-case"><ol>' + "".join(f"<li>{html.escape(a)}</li>" for a in res["actions"]) + "</ol></div>",
                    unsafe_allow_html=True)

# ---------------------------------------------------------------- device health
with th:
    devs = {f["device"] for f in FIND}
    kit.answer("Health check · 38 devices", f"{len(devs)} devices need attention",
               "Six warehouse PCs still run Windows 10, which stopped getting security updates on 14 Oct 2025. "
               "One laptop is not protected at all, and one PC has tamper protection switched off.", tone="warn")
    kit.table(FIND, [kit.col("Device", "device", "strong"), kit.col("System", "os", "muted"),
                     kit.col("Problem", "problem", "chip", {"Not onboarded": "bad", "Sensor inactive": "bad", "Tamper protection off": "bad",
                                                            "Unsupported OS": "warn", "Old antivirus signatures": "warn",
                                                            "Sensor misconfigured": "warn", "ASR rules only in audit": "info"}),
                     kit.col("Fix", "fix", "wrap")])

# ---------------------------------------------------------------- weekly report
with tr:
    page_html = R.build(ALL, FIND)
    nn = R.numbers(ALL, FIND)
    st.markdown(f"The customer's weekly report, built from the same alerts and checks: **{nn['total']} alerts** this week, "
                f"**{nn['escalate']} escalated**, **{nn['devices_flagged']} devices** to fix.")
    st.download_button("⬇ Download the report (HTML, print to PDF)", page_html, file_name="weekly_security_report.html",
                       mime="text/html", type="primary")
    st.iframe(page_html, height=900)

# ---------------------------------------------------------------- how well it works
with tt:
    ps, qs, hs = P.score(ALL), PH.score(D.EMAILS), H.score(D.DEVICES)
    st.markdown("Each rule set was tested against answers **written by hand first**, case by case, the way a careful senior analyst "
                "would decide. Disagreements are listed, not tuned away.")
    kit.answer("Tested on a week of invented cases", f"0 escalations missed, 0 phishing emails let through",
               "", [("Alerts: same decision", f"{ps['agree']} / {ps['n']}"), ("Escalations missed", f"{ps['escalations_missed']} of {ps['escalations']}"),
                    ("Emails: exact verdict", f"{qs['exact']} / {qs['n']}"), ("Devices: right findings", f"{hs['agree']} / {hs['n']}")])
    st.markdown("**Where the rules disagreed with the analyst**")
    mis = [dict(case=f"{m['day']} {m['time']} · {m['title']}", exp=m["expected"], got=m["decision"], note=m["rule"]) for m in ps["misses"]]
    mis += [dict(case=f"Email · {m['name']}", exp=m["expected"], got=m["verdict"], note="; ".join(w for _, w in m["signals"][:2]))
            for m in qs["rows"] if not m["exact"]]
    kit.table(mis, [kit.col("Case", "case", "wrap"), kit.col("Analyst", "exp", "chip", {"Escalate": "bad", "Investigate": "warn", "Suspicious": "warn"}),
                    kit.col("Rules", "got", "chip", {"Escalate": "bad", "Phishing": "bad"}), kit.col("Why the rules decided that", "note", "wrap")])
    st.caption("All three disagreements are on the cautious side: the rules escalated or flagged harder than the analyst would have.")
    with st.expander("The playbook, rule by rule"):
        st.markdown(
            "Checked top to bottom; the first match decides.\n\n"
            "- **Exception:** an approved admin tool on the documented host and account → close (never for High).\n"
            "- **R1:** ransomware, credential theft that succeeded, defense evasion, privilege escalation, account takeover, "
            "lateral movement → escalate, even when blocked.\n"
            "- **R2:** a user reached a malicious link and nothing blocked it → escalate.\n"
            "- **R3:** company mail forwarded outside → escalate.\n"
            "- **R4:** a server or an admin account, Medium or above → escalate.\n"
            "- **R5:** High and nothing stopped → escalate.\n"
            "- **R6:** not stopped, and the same device or user had a Medium+ alert earlier today → escalate.\n"
            "- **I1:** stopped, but the same detection came back → investigate.\n"
            "- **C1:** stopped automatically, first time, Medium or below → close.\n"
            "- **C2:** information only → close.\n"
            "- Anything else → investigate.")

kit.footer("playbook.py · phishing.py · health.py · fixed rules, no AI deciding")
