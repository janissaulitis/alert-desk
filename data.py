"""Invented data for Alert Desk: one customer (Baltic Freight SIA), a week of Defender-style alerts,
its devices and a set of emails. Nothing here is real. Titles follow Microsoft Defender's public naming.

Every alert and email carries `expected`: the decision a careful senior analyst would make,
written by hand per case BEFORE the rules in playbook.py / phishing.py were checked against it.
"""
CUSTOMER = "Baltic Freight SIA"
DOMAIN = "balticfreight.lv"
WEEK = "16–19 Nov 2026"
TODAY = "Thu 19 Nov"

# documented exceptions agreed with the customer (approved admin tools)
ALLOWLIST = [
    dict(device="IT-JUMP01", user="it.admin", titles=("PsExec used to run a remote command",
                                                     "Suspicious PowerShell command line"),
         note="Approved: IT patch checks from the admin jump host (change CHG-0412)"),
]

PRIVILEGED = {"it.admin", "adm.jansons"}

E, O, I, C = "Endpoint", "Office 365", "Identity", "Cloud Apps"

# day, time, severity, product, title, category, device, user, automatic action, clicked, detail, expected, why
_A = [
    # ---------------- today: the morning queue
    ("Thu", "06:12", "High", E, "Ransomware behavior detected in the file system", "ransomware", "FIN-LT-07", "l.ozola",
     "Blocked, device contained", False, "Mass file renames to .lock01 in Finance share; process blocked after 41 files",
     "Escalate", "Ransomware is always escalated, even when blocked: someone got code running"),
    ("Thu", "06:40", "Medium", E, "Malware detected and quarantined", "malware", "WH-PC-03", "warehouse1",
     "Quarantined", False, "Trojan:Win32/Wacatac.B!ml in Downloads\\invoice_viewer.exe",
     "Close", "Quarantined, first time on this device"),
    ("Thu", "07:05", "High", E, "Suspicious PowerShell command line", "execution", "SRV-FILE01", "svc.backup",
     "None", False, "Encoded command downloading from 45.133.x.x, run by the backup service account",
     "Escalate", "High on a server with nothing stopped"),
    ("Thu", "07:20", "Low", E, "PsExec used to run a remote command", "lateral movement", "IT-JUMP01", "it.admin",
     "None", False, "psexec \\\\WH-PC-01 patch-check.ps1",
     "Close", "Approved IT patch check from the jump host (documented exception)"),
    ("Thu", "07:31", "Medium", O, "Email messages containing malicious URL removed after delivery", "phishing", "-", "s.vitola",
     "Removed after delivery", False, "Fake Swedbank 'account locked' email, 14 recipients; nobody clicked",
     "Close", "Removed from all mailboxes, nobody clicked"),
    ("Thu", "07:32", "Medium", O, "A potentially malicious URL click was detected", "phishing", "-", "a.berzina",
     "None", True, "Same campaign: a.berzina opened the link 3 minutes before removal",
     "Escalate", "A user reached the phishing page: possible stolen password"),
    ("Thu", "07:45", "Medium", I, "Impossible travel activity", "suspicious sign-in", "-", "k.kalnins",
     "None", False, "Sign-ins from Riga 07:02 and Lagos 07:41, MFA passed on both",
     "Investigate", "Check VPN use and the sign-in details with the user"),
    ("Thu", "08:02", "High", E, "Suspicious access to LSASS service", "credential theft", "ACC-PC-05", "d.liepa",
     "None", False, "Unsigned tool read LSASS memory",
     "Escalate", "Credential theft attempt"),
    ("Thu", "08:10", "Medium", C, "Suspicious inbox forwarding rule", "exfiltration", "-", "j.saulite",
     "None", False, "New rule forwards all mail with 'invoice' to an outside Gmail address",
     "Escalate", "Forwarding company mail outside is a classic sign of a taken-over mailbox"),
    ("Thu", "08:15", "Low", E, "Unwanted software detected", "unwanted software", "MKT-LT-02", "e.krumina",
     "Quarantined", False, "Adware bundled with a PDF converter",
     "Close", "Quarantined adware"),
    ("Thu", "08:20", "Informational", E, "Antivirus detected potentially unwanted application", "unwanted software", "HR-PC-01", "m.grins",
     "Blocked", False, "Toolbar installer blocked",
     "Close", "Blocked, informational"),
    ("Thu", "08:25", "Medium", E, "Suspicious Office macro behavior", "execution", "ACC-PC-05", "d.liepa",
     "None", False, "Excel macro started cmd.exe",
     "Escalate", "Same device as the LSASS alert this morning: treat as one incident"),
    ("Thu", "08:31", "High", O, "A potentially malicious URL click was detected", "phishing", "-", "j.liepa",
     "Blocked by Safe Links", True, "Click on a DocuSign look-alike link, blocked before the page loaded",
     "Investigate", "Blocked before loading: confirm the block and check who else got it"),
    ("Thu", "08:40", "Medium", I, "Anonymous IP address sign-in", "suspicious sign-in", "-", "adm.jansons",
     "None", False, "Admin account signed in from a Tor exit node",
     "Escalate", "Privileged account"),
    ("Thu", "08:42", "Medium", I, "Unfamiliar sign-in properties", "suspicious sign-in", "-", "r.petersons",
     "None", False, "New browser and Tallinn location, MFA passed",
     "Investigate", "Likely travel; confirm with the user"),
    ("Thu", "08:50", "Low", E, "Suspicious scheduled task", "persistence", "IT-JUMP01", "it.admin",
     "None", False, "Task 'UpdaterSvc' runs a script from C:\\Users\\Public",
     "Investigate", "Not part of the documented exception; check what the task runs"),
    ("Thu", "09:00", "Medium", E, "Malware detected and quarantined", "malware", "SRV-APP02", "svc.app",
     "Quarantined", False, "HackTool:Win32/Mimikatz in a temp folder",
     "Escalate", "A server, and a credential-dumping tool: how did it get there?"),
    ("Thu", "09:12", "Medium", E, "Suspicious PowerShell command line", "execution", "WH-PC-03", "warehouse1",
     "None", False, "PowerShell contacting a new domain, after this morning's quarantined Trojan",
     "Escalate", "Same device as the 06:40 malware: it may not be fully cleaned"),
    ("Thu", "09:20", "Low", C, "Mass download by a single user", "exfiltration", "-", "m.grins",
     "None", False, "2,300 files downloaded from the HR SharePoint site in 10 minutes",
     "Investigate", "Could be a legitimate export; ask HR before escalating"),
    ("Thu", "09:25", "Medium", C, "Activity from infrequent country", "suspicious sign-in", "-", "e.krumina",
     "None", False, "OneDrive activity from Portugal",
     "Investigate", "Confirm travel with the user"),
    ("Thu", "09:31", "Informational", O, "Email reported by user as malware or phish", "phishing", "-", "s.vitola",
     "None", False, "User reported a 'parcel fee' SMS-style email",
     "Investigate", "Check the reported email (Phishing check)"),
    ("Thu", "09:40", "High", E, "Attempt to turn off Microsoft Defender Antivirus protection", "defense evasion", "LOG-PC-04", "t.ozols",
     "Blocked by tamper protection", False, "Registry change to disable real-time protection, blocked",
     "Escalate", "Someone tried to switch protection off: attacker behaviour"),
    ("Thu", "09:45", "Low", E, "Unwanted software detected", "unwanted software", "ACC-PC-05", "d.liepa",
     "Quarantined", False, "Browser extension adware",
     "Close", "Quarantined adware; the device is already escalated for the LSASS alert"),
    ("Thu", "09:52", "Medium", E, "Malware detected and quarantined", "malware", "MKT-LT-02", "e.krumina",
     "Quarantine failed", False, "Trojan:JS/Phonzy in browser cache, quarantine failed",
     "Investigate", "Run a full scan and retry remediation"),
    # ---------------- earlier this week (test cases)
    ("Mon", "10:14", "High", E, "Suspicious process injection observed", "execution", "SAL-LT-01", "a.dumins",
     "None", False, "rundll32 injected into explorer.exe",
     "Escalate", "High, nothing stopped"),
    ("Mon", "11:02", "Medium", I, "Password spray attack", "credential theft", "-", "(many users)",
     "None", False, "Failed sign-ins for 37 accounts from one IP; no success",
     "Investigate", "No successful sign-in: block the IP, watch for success"),
    ("Mon", "11:40", "High", I, "Password spray attack", "credential theft", "-", "p.lacis",
     "None", True, "Same IP; one successful sign-in for p.lacis",
     "Escalate", "One account was taken over"),
    ("Mon", "13:05", "Medium", O, "Suspicious email sending patterns detected", "account compromise", "-", "g.vilks",
     "User restricted from sending", False, "400 emails in 20 minutes to outside addresses",
     "Escalate", "Mailbox probably taken over, even though sending is now blocked"),
    ("Mon", "14:20", "Informational", E, "Antivirus detected potentially unwanted application", "unwanted software", "WH-PC-02", "warehouse2",
     "Blocked", False, "Crypto miner installer blocked",
     "Close", "Blocked"),
    ("Tue", "09:10", "Low", E, "PsExec used to run a remote command", "lateral movement", "SAL-LT-03", "k.jansone",
     "None", False, "Sales laptop ran PsExec against SRV-FILE01",
     "Escalate", "Remote-execution tool from an ordinary user's laptop, aimed at a server"),
    ("Tue", "10:30", "Medium", C, "Unusual file deletion activity", "impact", "-", "o.balode",
     "None", False, "1,900 OneDrive files deleted in 15 minutes",
     "Investigate", "Check whether it was a clean-up or something worse"),
    ("Tue", "12:45", "High", O, "Email messages containing malware removed after delivery", "malware", "-", "(6 users)",
     "Removed after delivery", False, "ISO attachment, removed; no one opened it",
     "Investigate", "High: confirm nobody opened it before removal"),
    ("Tue", "15:00", "Medium", I, "Suspicious additions to sensitive groups", "privilege escalation", "-", "adm.jansons",
     "None", False, "t.ozols added to Domain Admins outside a change window",
     "Escalate", "Admin rights given outside the change process"),
    ("Wed", "08:55", "Low", E, "Suspicious scheduled task", "persistence", "SAL-LT-02", "i.berzs",
     "None", False, "Task runs an unsigned exe at log-on",
     "Investigate", "Check what the exe is"),
    ("Wed", "09:40", "Medium", E, "Malware detected and quarantined", "malware", "LOG-PC-01", "logistics1",
     "Quarantined", False, "Trojan:Win32/Agent, first detection",
     "Close", "Quarantined, first time"),
    ("Wed", "13:15", "Medium", E, "Malware detected and quarantined", "malware", "LOG-PC-01", "logistics1",
     "Quarantined", False, "Same Trojan again 3.5 hours later",
     "Investigate", "Came back: find where it keeps coming from"),
    ("Wed", "14:00", "High", E, "Ransomware behavior detected in the file system", "ransomware", "WH-PC-05", "warehouse3",
     "Blocked, device contained", False, "Shadow copies deletion attempt, blocked",
     "Escalate", "Ransomware is always escalated"),
    ("Wed", "16:20", "Medium", I, "Impossible travel activity", "suspicious sign-in", "-", "a.dumins",
     "None", False, "Riga and Frankfurt 20 min apart; Frankfurt is a known VPN exit",
     "Investigate", "Probably VPN; confirm"),
    ("Wed", "17:05", "Informational", O, "Admin submission result completed", "phishing", "-", "-",
     "None", False, "Microsoft confirmed a submitted email as phishing",
     "Close", "Information only"),
    ("Wed", "17:30", "Medium", E, "Suspicious PowerShell command line", "execution", "IT-JUMP01", "it.admin",
     "None", False, "patch-check.ps1 run from the jump host",
     "Close", "Approved IT patch check (documented exception)"),
]

FIELDS = ["day", "time", "severity", "product", "title", "category", "device", "user", "auto", "clicked", "detail",
          "expected", "why"]
ALERTS = [dict(zip(FIELDS, a), id=f"da{1000 + i}") for i, a in enumerate(_A)]
for a in ALERTS:
    a["privileged"] = a["user"] in PRIVILEGED
    a["server"] = a["device"].startswith("SRV-")


# ---------------- devices (for health checks)
def _devices():
    rows = []
    groups = [("FIN-LT", 8, "Windows 11 24H2"), ("ACC-PC", 6, "Windows 11 23H2"), ("WH-PC", 6, "Windows 10 22H2"),
              ("LOG-PC", 5, "Windows 11 24H2"), ("SAL-LT", 5, "Windows 11 24H2"), ("MKT-LT", 3, "macOS 15"),
              ("HR-PC", 2, "Windows 11 23H2")]
    for prefix, n, os_ in groups:
        for i in range(1, n + 1):
            rows.append(dict(device=f"{prefix}-{i:02d}", os=os_, sensor="Active", last_seen_h=1, sig_age_d=0,
                             tamper="On", asr="Block", onboarded=True))
    rows += [dict(device="SRV-FILE01", os="Windows Server 2022", sensor="Active", last_seen_h=0, sig_age_d=0, tamper="On", asr="Block", onboarded=True),
             dict(device="SRV-APP02", os="Windows Server 2019", sensor="Active", last_seen_h=0, sig_age_d=0, tamper="On", asr="Audit", onboarded=True),
             dict(device="IT-JUMP01", os="Windows Server 2022", sensor="Active", last_seen_h=0, sig_age_d=0, tamper="On", asr="Block", onboarded=True)]
    by = {r["device"]: r for r in rows}
    # the real findings, written by hand
    by["WH-PC-02"].update(sig_age_d=6)
    by["WH-PC-04"].update(sensor="Inactive", last_seen_h=9 * 24)
    by["LOG-PC-03"].update(tamper="Off")
    by["FIN-LT-05"].update(asr="Audit")
    by["FIN-LT-06"].update(asr="Audit")
    by["SAL-LT-04"].update(sig_age_d=4, sensor="Misconfigured")
    by["MKT-LT-03"].update(onboarded=False, sensor="Not onboarded")
    return rows


DEVICES = _devices()
for d in DEVICES:
    d["expected"] = []
_EXP = {"WH-PC-01": ["Unsupported OS"], "WH-PC-02": ["Unsupported OS", "Old antivirus signatures"],
        "WH-PC-03": ["Unsupported OS"], "WH-PC-04": ["Unsupported OS", "Sensor inactive"], "WH-PC-05": ["Unsupported OS"],
        "WH-PC-06": ["Unsupported OS"], "LOG-PC-03": ["Tamper protection off"], "FIN-LT-05": ["ASR rules only in audit"],
        "FIN-LT-06": ["ASR rules only in audit"], "SRV-APP02": ["ASR rules only in audit"],
        "SAL-LT-04": ["Old antivirus signatures", "Sensor misconfigured"], "MKT-LT-03": ["Not onboarded"]}
for d in DEVICES:
    d["expected"] = sorted(_EXP.get(d["device"], []))


# ---------------- emails for the phishing check (16, LV and EN)
def _mail(name, frm, subject, body, auth="pass", reply_to="", links=(), attach=(), expected="", why=""):
    spf, dkim, dmarc = (auth.split("/") * 3)[:3] if "/" in auth else (auth, auth, auth)
    return dict(name=name, from_name=frm[0], from_addr=frm[1], reply_to=reply_to, subject=subject, body=body,
                spf=spf, dkim=dkim, dmarc=dmarc, links=list(links), attachments=list(attach), expected=expected, why=why)


EMAILS = [
    _mail("Swedbank: account locked", ("Swedbank", "drosiba@swedbank-lv-security.com"),
          "Jūsu konts tiks bloķēts 24 stundu laikā",
          "Labdien! Mēs pamanījām aizdomīgu darbību. Lūdzu, nekavējoties apstipriniet savus datus, citādi konts tiks bloķēts.",
          auth="fail", links=[("swedbank.lv", "http://swedbank-lv-security.com/login")],
          expected="Phishing", why="Bank look-alike domain, failed authentication, link text hides the real address"),
    _mail("Microsoft 365: password expires", ("Microsoft 365", "it-support@m365-account-helpdesk.co"),
          "Your password expires today",
          "Your password expires today. Keep your current password by verifying your account below.",
          auth="none", links=[("Keep my password", "https://login.microsoftonline.com.verify-user.ru/")],
          expected="Phishing", why="Microsoft sign-in look-alike link on a .ru domain"),
    _mail("CEO asks for an urgent transfer", ("Andris Kalniņš", "andris.kalnins@baltlcfreight.lv"),
          "Steidzami – maksājums šodien",
          "Sveiki, vajag šodien veikt steidzamu pārskaitījumu jaunam piegādātājam. Lūdzu, nezvaniet, esmu sapulcē. Rekvizītus atsūtīšu.",
          auth="pass", reply_to="andris.kalnins.ceo@gmail.com",
          expected="Phishing", why="Company look-alike domain (l for i), reply goes to Gmail, urgent payment"),
    _mail("DPD: customs fee", ("DPD Latvija", "info@dpd-paku-serviss.lv"),
          "Jūsu sūtījums gaida muitas nodevas samaksu (1,99 EUR)",
          "Lai saņemtu sūtījumu, lūdzu samaksājiet 1,99 EUR muitas nodevu.",
          auth="softfail", links=[("Maksāt tagad", "https://bit.ly/3dpdLV")],
          expected="Phishing", why="Courier look-alike, short link to a payment page"),
    _mail("VID tax refund", ("VID", "atmaksa@vid-eds-atmaksa.com"), "Jums pienākas nodokļu atmaksa",
          "Pielikumā atradīsiet atmaksas veidlapu. Aizpildiet to 48 stundu laikā.",
          auth="fail", attach=["VID_atmaksa_2026.html"],
          expected="Phishing", why="Tax office look-alike, HTML attachment (fake sign-in page)"),
    _mail("Supplier invoice in a ZIP", ("Rīgas Iepakojums SIA", "gramatvediba@rigasiepakojums.lv"),
          "Rēķins Nr. 2026-1184", "Labdien, pielikumā rēķins par novembri.",
          auth="pass", attach=["Rekins_2026-1184.zip"],
          expected="Suspicious", why="Known supplier and authentication passes, but invoices rarely come zipped"),
    _mail("Omniva parcel notice", ("Omniva", "info@omniva.lv"), "Sūtījums ir pakomātā",
          "Jūsu sūtījums ir pakomātā Rīga Akropole. Kods: 448812.",
          auth="pass", links=[("Sekot sūtījumam", "https://www.omniva.lv/track/448812")],
          expected="Safe", why="Real domain, authentication passes, link goes where it says"),
    _mail("Internal IT notice", ("Baltic Freight IT", "it@balticfreight.lv"), "Planned maintenance Saturday",
          "File server maintenance on Saturday 08:00–10:00. Details on the intranet.",
          auth="pass", links=[("Intranet", "https://intranet.balticfreight.lv/maintenance")],
          expected="Safe", why="Internal, authenticated, internal link"),
    _mail("Swedbank newsletter", ("Swedbank", "zinas@swedbank.lv"), "Novembra jaunumi uzņēmumiem",
          "Jaunumi par maksājumu termiņiem svētku laikā.",
          auth="pass", links=[("Lasīt vairāk", "https://www.swedbank.lv/business/news")],
          expected="Safe", why="Real bank domain, authenticated"),
    _mail("DocuSign look-alike", ("DocuSign", "dse@docusign-review.net"), "Please review and sign: Contract_BF_2026.pdf",
          "You have received a document to review and sign.",
          auth="fail", links=[("REVIEW DOCUMENT", "https://xn--dcusign-ofa.net/s/88a1")],
          expected="Phishing", why="Look-alike sender and a punycode link (disguised letters)"),
    _mail("Real DocuSign", ("DocuSign", "dse_na4@docusign.net"), "Please DocuSign: Lease_Riga_Office.pdf",
          "Inga Ozola sent you a document to review and sign.",
          auth="pass", links=[("REVIEW DOCUMENT", "https://na4.docusign.net/Signing/EmailStart.aspx?a=3f2")],
          expected="Safe", why="Real DocuSign domain, authenticated"),
    _mail("Partner changes bank details", ("Nordic Shipping AB", "accounts@nordicshipping.se"),
          "Updated bank details for future payments",
          "Please note our bank account has changed. Use the new IBAN for all invoices from today.",
          auth="pass", reply_to="accounts.nordicshipping@outlook.com",
          expected="Suspicious", why="Real partner domain, but a bank-detail change with replies going elsewhere: call them to confirm"),
    _mail("Latvenergo bill", ("Latvenergo", "rekini@latvenergo.lv"), "Jūsu rēķins par oktobri",
          "Rēķins par elektroenerģiju ir pieejams portālā.",
          auth="pass", links=[("Skatīt rēķinu", "https://www.elektrum.lv/lv/mans-elektrum")],
          expected="Safe", why="Real energy company, link to its own customer portal"),
    _mail("Spoofed IT reset", ("Baltic Freight IT", "it@balticfreight.lv"), "Password reset required",
          "All staff must reset passwords today using the link below.",
          auth="fail", links=[("Reset now", "http://185.244.25.17/reset")],
          expected="Phishing", why="Pretends to be internal IT, fails authentication, link is a bare IP address"),
    _mail("SaaS newsletter", ("Trello", "do-not-reply@trello.com"), "What's new in Trello this month",
          "New features for boards and automation. Unsubscribe anytime.",
          auth="pass", links=[("See what's new", "https://trello.com/whats-new"), ("Unsubscribe", "https://trello.com/unsubscribe")],
          expected="Safe", why="Known service, authenticated, own links"),
    _mail("Teams voicemail", ("Microsoft Teams", "voicemail@teams-notify-center.com"), "You have a new voicemail (0:47)",
          "You received a voicemail from +371 2xxx xxxx. Open the attachment to listen.",
          auth="fail", attach=["Voicemail_0047.htm"],
          expected="Phishing", why="Teams look-alike sender, .htm attachment"),
]
