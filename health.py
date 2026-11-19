"""Endpoint and server health checks, following written internal guidelines."""

CHECKS = [
    ("Unsupported OS", lambda d: d["os"].startswith("Windows 10"),
     "Windows 10 lost security updates on 14 Oct 2025", "Upgrade to Windows 11, or enrol in Extended Security Updates"),
    ("Not onboarded", lambda d: not d["onboarded"],
     "Device is not protected by Defender for Endpoint", "Onboard the device"),
    ("Sensor inactive", lambda d: d["onboarded"] and (d["sensor"] == "Inactive" or d["last_seen_h"] > 7 * 24),
     "No data from the device for over 7 days", "Check whether the device is still in use; reconnect it or offboard it"),
    ("Sensor misconfigured", lambda d: d["sensor"] == "Misconfigured",
     "The device reports only partly", "Fix the sensor's network access (proxy / telemetry endpoints)"),
    ("Old antivirus signatures", lambda d: d["onboarded"] and d["sig_age_d"] >= 3,
     "Signatures older than 3 days", "Force a signature update and check the update source"),
    ("Tamper protection off", lambda d: d["tamper"] == "Off",
     "Anyone with admin rights can switch protection off", "Turn tamper protection on in the Defender portal"),
    ("ASR rules only in audit", lambda d: d["asr"] == "Audit",
     "Attack surface reduction rules only log, they don't block", "Review audit events, then switch the rules to block"),
]
WEIGHT = {"Not onboarded": 3, "Sensor inactive": 3, "Tamper protection off": 3, "Unsupported OS": 2,
          "Old antivirus signatures": 2, "Sensor misconfigured": 2, "ASR rules only in audit": 1}


def run(devices):
    findings = []
    for d in devices:
        for name, test, why, fix in CHECKS:
            if test(d):
                findings.append(dict(device=d["device"], os=d["os"], problem=name, why=why, fix=fix, weight=WEIGHT[name]))
    findings.sort(key=lambda f: (-f["weight"], f["device"]))
    return findings


def score(devices):
    got = {}
    for f in run(devices):
        got.setdefault(f["device"], []).append(f["problem"])
    rows = [dict(device=d["device"], expected=d["expected"], got=sorted(got.get(d["device"], []))) for d in devices]
    return dict(n=len(rows), agree=sum(r["expected"] == r["got"] for r in rows), misses=[r for r in rows if r["expected"] != r["got"]])
