"""The triage playbook: fixed, readable rules that decide what happens to each alert.
Close / Investigate / Escalate, the rule that decided it, the next steps and the hunting query to run.
"""
from data import ALLOWLIST

SEV_ORDER = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3}
# example service levels: time to first response, in minutes
SLA_MIN = {"High": 60, "Medium": 240, "Low": 480, "Informational": 1440}

ALWAYS_ESCALATE = {"ransomware", "credential theft", "defense evasion", "privilege escalation", "account compromise",
                   "lateral movement"}
FIXED = {"Quarantined", "Blocked", "Removed after delivery", "Blocked, device contained", "Blocked by Safe Links",
         "Blocked by tamper protection", "User restricted from sending"}


def _allowlisted(a):
    for rule in ALLOWLIST:
        if a["device"] == rule["device"] and a["user"] == rule["user"] and a["title"] in rule["titles"]:
            return rule["note"]
    return None


def decide(a, earlier):
    """a: the alert. earlier: alerts that came in before it on the same day.
    Returns (decision, rule) — rules are checked top to bottom, the first match wins."""
    sev = SEV_ORDER[a["severity"]]
    fixed = a["auto"] in FIXED
    same_entity_before = [e for e in earlier if (a["device"] != "-" and e["device"] == a["device"]) or
                          (a["user"] not in ("-",) and not a["user"].startswith("(") and e["user"] == a["user"])]
    repeat = [e for e in same_entity_before if e["title"] == a["title"]]

    note = _allowlisted(a)
    if note and sev <= SEV_ORDER["Medium"]:
        return "Close", f"Documented exception: {note}"
    if a["category"] == "credential theft" and a["clicked"]:
        return "Escalate", "R1 · a sign-in succeeded during a credential attack"
    if a["category"] in ALWAYS_ESCALATE and not (a["category"] == "credential theft" and sev < SEV_ORDER["High"]):
        return "Escalate", f"R1 · '{a['category']}' is always escalated, even when blocked"
    if a["clicked"] and not fixed:
        return "Escalate", "R2 · a user reached a malicious link and nothing blocked it"
    if a["category"] == "exfiltration" and "forwarding" in a["title"].lower():
        return "Escalate", "R3 · company mail forwarded outside"
    if a["server"] and sev >= SEV_ORDER["Medium"]:
        return "Escalate", "R4 · a server is involved"
    if a["privileged"] and sev >= SEV_ORDER["Medium"]:
        return "Escalate", "R4 · an admin account is involved"
    if sev == SEV_ORDER["High"] and not fixed:
        return "Escalate", "R5 · high severity and nothing was stopped"
    if not fixed and any(SEV_ORDER[e["severity"]] >= SEV_ORDER["Medium"] for e in same_entity_before):
        return "Escalate", "R6 · same device or user had another alert earlier today"
    if fixed and repeat:
        return "Investigate", "I1 · fixed, but the same detection came back"
    if fixed and sev <= SEV_ORDER["Medium"]:
        return "Close", "C1 · stopped automatically, first time"
    if a["severity"] == "Informational" and "reported by user" not in a["title"].lower():
        return "Close", "C2 · information only"
    return "Investigate", "I2 · needs a look: no rule says close or escalate"


STEPS = {
    "Escalate": ["Isolate the device or disable the account if the playbook allows", "Open an incident and hand over to L2 with the evidence",
                 "Tell the customer's contact within the service level"],
    "Investigate": ["Review the evidence and the timeline", "Run the hunting query below", "Contact the user if needed, then close or escalate"],
    "Close": ["Confirm the automatic action worked", "Close with a short note"],
}
EXTRA = {
    "phishing": "Check the email in Phishing check; if anyone entered a password: reset it and revoke sessions",
    "suspicious sign-in": "Compare with the user's usual locations and devices; confirm travel or VPN",
    "credential theft": "Reset passwords of affected accounts and revoke sessions",
    "malware": "Run a full scan; find where the file came from",
    "exfiltration": "Remove the forwarding rule; check what was sent",
    "ransomware": "Keep the device isolated; check shares it could reach",
}


def kql(a):
    t, dev, user = a["title"].lower(), a["device"], a["user"]
    if a["product"] == "Endpoint" and ("powershell" in t or "macro" in t or "injection" in t or "psexec" in t or "scheduled task" in t):
        return (f'DeviceProcessEvents\n| where Timestamp > ago(24h)\n| where DeviceName =~ "{dev}"\n'
                '| where FileName in~ ("powershell.exe", "cmd.exe", "rundll32.exe", "psexec.exe", "schtasks.exe")\n'
                '| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName\n| order by Timestamp asc')
    if a["product"] == "Endpoint" and ("ransomware" in t):
        return (f'DeviceFileEvents\n| where Timestamp > ago(6h)\n| where DeviceName =~ "{dev}"\n'
                '| where ActionType in ("FileRenamed", "FileModified")\n| summarize Files = count() by bin(Timestamp, 5m), InitiatingProcessFileName\n| order by Timestamp asc')
    if a["product"] == "Endpoint" and "lsass" in t:
        return (f'DeviceEvents\n| where Timestamp > ago(24h)\n| where DeviceName =~ "{dev}"\n'
                '| where ActionType == "OpenProcessApiCall" and FileName =~ "lsass.exe"\n'
                '| project Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName')
    if a["product"] == "Endpoint":
        return (f'AlertEvidence\n| where Timestamp > ago(7d)\n| where DeviceName =~ "{dev}"\n'
                '| join kind=inner (AlertInfo) on AlertId\n| project Timestamp, Title, Severity, FileName, SHA256\n| order by Timestamp desc')
    if a["product"] == "Office 365":
        return ('UrlClickEvents\n| where Timestamp > ago(24h)\n'
                f'| where AccountUpn startswith "{user}"\n| project Timestamp, Url, ActionType, IsClickedThrough, NetworkMessageId')
    if a["product"] == "Identity":
        return ('IdentityLogonEvents\n| where Timestamp > ago(7d)\n'
                f'| where AccountName =~ "{user}"\n| summarize SignIns = count() by Location, IPAddress, DeviceName\n| order by SignIns desc')
    return ('CloudAppEvents\n| where Timestamp > ago(24h)\n'
            f'| where AccountDisplayName has "{user}"\n| summarize Actions = count() by ActionType, CountryCode\n| order by Actions desc')


def triage(alerts):
    """Decide every alert in order of arrival. Returns new dicts with decision, rule, steps, kql, sla."""
    out, by_day = [], {}
    for a in sorted(alerts, key=lambda x: (["Mon", "Tue", "Wed", "Thu", "Fri"].index(x["day"]), x["time"])):
        earlier = by_day.setdefault(a["day"], [])
        decision, rule = decide(a, earlier)
        steps = list(STEPS[decision]) + ([EXTRA[a["category"]]] if a["category"] in EXTRA and decision != "Close" else [])
        out.append({**a, "decision": decision, "rule": rule, "steps": steps, "kql": kql(a), "sla_min": SLA_MIN[a["severity"]],
                    "agrees": decision == a["expected"]})
        earlier.append(a)
    return out


def score(results):
    must = [r for r in results if r["expected"] == "Escalate"]
    return dict(n=len(results), agree=sum(r["agrees"] for r in results),
                escalations=len(must), escalations_missed=sum(r["decision"] != "Escalate" for r in must),
                misses=[r for r in results if not r["agrees"]])
