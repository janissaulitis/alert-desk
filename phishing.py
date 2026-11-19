"""Phishing check: fixed rules over an email's sender, authentication results, links and attachments.
Each signal adds points and explains itself. Verdict: Phishing (≥5), Suspicious (2–4), Looks safe (<2).
"""
import re
import unicodedata
from urllib.parse import urlparse

from data import DOMAIN

# brands the customer deals with: name -> real domains
BRANDS = {
    "swedbank": ["swedbank.lv", "swedbank.com"], "seb": ["seb.lv"], "citadele": ["citadele.lv"],
    "microsoft": ["microsoft.com", "microsoftonline.com", "office.com", "live.com"],
    "docusign": ["docusign.net", "docusign.com"], "dpd": ["dpd.lv", "dpd.com"], "omniva": ["omniva.lv"],
    "latvenergo": ["latvenergo.lv", "elektrum.lv"], "vid": ["vid.gov.lv"], "teams": ["microsoft.com"],
    "trello": ["trello.com", "atlassian.com"], "baltic freight": [DOMAIN],
}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "cutt.ly", "rb.gy", "is.gd"}
RISKY_ATTACH = {".html": "a web page that can show a fake sign-in", ".htm": "a web page that can show a fake sign-in",
                ".iso": "a disk image that hides programs", ".img": "a disk image that hides programs",
                ".js": "a script", ".vbs": "a script", ".lnk": "a shortcut that runs commands", ".exe": "a program",
                ".scr": "a program", ".docm": "a document with macros", ".xlsm": "a spreadsheet with macros"}
ARCHIVES = {".zip", ".rar", ".7z"}
URGENT = ["steidzami", "nekavējoties", "tiks bloķēts", "24 stundu", "48 stundu", "šodien", "urgent", "immediately",
          "expires today", "today", "within 24", "locked", "suspended"]
MONEY = ["pārskaitījum", "maksājum", "samaksā", "iban", "bank details", "bank account", "transfer", "payment", "rekvizīt"]


def domain_of(addr):
    return addr.rsplit("@", 1)[-1].lower().strip(">") if "@" in addr else addr.lower()


def host_of(url):
    try:
        return (urlparse(url if "://" in url else "http://" + url).hostname or "").lower()
    except ValueError:
        return ""


def registrable(host):
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _lev(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike(dom):
    """Returns the real domain a sender domain imitates, if any."""
    d = registrable(dom)
    for brand, real in BRANDS.items():
        if d in real:
            return None
    for brand, real in BRANDS.items():
        key = brand.replace(" ", "")
        if key in d.replace("-", "").replace(".", ""):
            return real[0]
        for r in real:
            if _lev(d.split(".")[0], r.split(".")[0]) == 1 and len(r.split(".")[0]) > 4:
                return r
    return None


def check(m):
    """m: dict with from_name, from_addr, reply_to, spf, dkim, dmarc, subject, body, links [(text, href)], attachments."""
    sig = []

    def add(points, what):
        sig.append((points, what))

    dom = domain_of(m["from_addr"])
    real = lookalike(dom)
    known = any(registrable(dom) in r for r in BRANDS.values())
    if real:
        add(3, f"Sender domain {dom} imitates {real}")
    name = m["from_name"].lower()
    for brand, doms in BRANDS.items():
        if brand in name and registrable(dom) not in doms and not real:
            add(2, f"Display name says {m['from_name']} but the address is {dom}")
            break

    auth = [m["spf"], m["dkim"], m["dmarc"]]
    if m["dmarc"] == "fail" or m["spf"] == "fail":
        add(2 if (real or known) else 1, "Sender authentication failed (SPF/DMARC)" + (" for a known name" if (real or known) else ""))
    elif "softfail" in auth or "none" in auth:
        add(1, "Sender authentication is missing or weak")

    if m.get("reply_to") and domain_of(m["reply_to"]) != dom:
        add(2, f"Replies would go to a different address: {m['reply_to']}")

    for text, href in m["links"]:
        h = host_of(href)
        shown = host_of(text) if "." in text and " " not in text else ""
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", h):
            add(3, f"Link goes to a bare IP address ({h})")
        elif h.startswith("xn--") or ".xn--" in h:
            add(3, f"Link uses disguised letters (punycode): {h}")
        elif registrable(h) in SHORTENERS:
            add(2, f"Link is shortened, hiding where it goes ({h})")
        if shown and registrable(shown) != registrable(h):
            add(3, f"Link text shows {shown} but goes to {h}")
        hl = lookalike(h)
        if hl and not (shown and registrable(shown) != registrable(h)):
            add(2, f"Link goes to a look-alike of {hl}: {h}")
        elif any(b in h for b in ("microsoftonline", "login.", "signin", "verify")) and not any(registrable(h) in r for r in BRANDS.values()):
            add(3, f"Sign-in style link on an unrelated domain: {h}")

    for f in m["attachments"]:
        ext = "." + f.rsplit(".", 1)[-1].lower()
        if ext in RISKY_ATTACH:
            add(3, f"Attachment {f} is {RISKY_ATTACH[ext]}")
        elif ext in ARCHIVES:
            add(2, f"Attachment {f} is an archive, which can hide programs")

    text = (m["subject"] + " " + m["body"]).lower()
    if any(w in text for w in URGENT):
        add(1, "Pressure to act fast")
    if any(w in text for w in MONEY):
        add(2 if (m.get("reply_to") or real) else 1, "Asks about payments or bank details")

    pts = sum(p for p, _ in sig)
    verdict = "Phishing" if pts >= 5 else "Suspicious" if pts >= 2 else "Looks safe"
    return dict(verdict=verdict, points=pts, signals=sorted(sig, key=lambda s: -s[0]), actions=actions(verdict, m))


def actions(verdict, m):
    if verdict == "Phishing":
        return ["Remove it from every mailbox (Threat Explorer: soft delete)",
                "Block the sender domain and the link addresses (Tenant Allow/Block List)",
                "Check who clicked (UrlClickEvents); for anyone who entered a password: reset it and revoke sessions",
                "Submit it to Microsoft as phishing and reply to the user who reported it"]
    if verdict == "Suspicious":
        return ["Hold it: ask the user not to open links or attachments yet",
                "Confirm with the sender by phone, using a number you already have, not one from the email",
                "Detonate the attachment in a sandbox before releasing it"]
    return ["Tell the user it looks fine, and thank them for reporting"]


def parse_raw(raw):
    """Paste-in email (headers + body) -> dict for check()."""
    head, _, body = raw.replace("\r\n", "\n").partition("\n\n")
    hdr = {}
    for line in re.split(r"\n(?=[A-Za-z-]+:)", head):
        if ":" in line:
            k, v = line.split(":", 1)
            hdr[k.strip().lower()] = " ".join(v.split())
    frm = hdr.get("from", "")
    mname = re.match(r'\s*"?([^"<]*)"?\s*<([^>]+)>', frm)
    from_name, from_addr = (mname.group(1).strip(), mname.group(2).strip()) if mname else ("", frm.strip())
    rt = re.search(r"<([^>]+)>", hdr.get("reply-to", "")) or re.search(r"(\S+@\S+)", hdr.get("reply-to", ""))
    ar = hdr.get("authentication-results", "").lower()

    def res(k):
        mm = re.search(k + r"=(\w+)", ar)
        return mm.group(1) if mm else "none"

    links = re.findall(r"\[([^\]]+)\]\((\S+)\)", body) + [(u, u) for u in re.findall(r"(?<![\(\[])https?://\S+", body)]
    att = re.findall(r"(?im)^attachment:\s*(\S+)", raw) + re.findall(r'filename="?([^";\n]+)', raw)
    clean = re.sub(r"\[([^\]]+)\]\((\S+)\)", r"\1", body)
    return dict(from_name=from_name, from_addr=from_addr, reply_to=rt.group(1) if rt else "", spf=res("spf"),
                dkim=res("dkim"), dmarc=res("dmarc"), subject=hdr.get("subject", ""), body=clean, links=links, attachments=att)


def to_raw(m):
    """The sample emails written out as a pasteable message."""
    lines = [f'From: "{m["from_name"]}" <{m["from_addr"]}>', f"To: staff@{DOMAIN}"]
    if m.get("reply_to"):
        lines.append(f"Reply-To: <{m['reply_to']}>")
    lines += [f"Subject: {m['subject']}",
              f"Authentication-Results: mx.{DOMAIN}; spf={m['spf']}; dkim={m['dkim']}; dmarc={m['dmarc']}"]
    lines += [f"Attachment: {a}" for a in m["attachments"]]
    body = m["body"] + "".join(f"\n\n[{t}]({h})" for t, h in m["links"])
    return "\n".join(lines) + "\n\n" + body


def score(emails):
    rows = []
    for m in emails:
        r = check(parse_raw(to_raw(m)))
        ok = (r["verdict"] == "Looks safe") == (m["expected"] == "Safe") and \
             (m["expected"] != "Phishing" or r["verdict"] in ("Phishing", "Suspicious"))
        exact = {"Looks safe": "Safe"}.get(r["verdict"], r["verdict"]) == m["expected"]
        rows.append({**m, **r, "ok": ok, "exact": exact})
    phish = [r for r in rows if r["expected"] == "Phishing"]
    return dict(rows=rows, n=len(rows), exact=sum(r["exact"] for r in rows),
                phishing=len(phish), phishing_missed=sum(r["verdict"] == "Looks safe" for r in phish),
                false_alarms=[r for r in rows if r["expected"] == "Safe" and r["verdict"] != "Looks safe"])
