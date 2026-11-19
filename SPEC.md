# Alert Desk — spec

A morning at a managed endpoint security desk, for one invented customer (Baltic Freight SIA, ~40 devices).
Built to show the daily work of a junior security analyst, mapped to the duties in Atea's Junior Security Analyst ad.

## What it does (mapped to the job)

| Atea duty | In the app |
|---|---|
| Review and handle security alerts, escalate high/critical per procedure | **Queue**: every alert gets Close / Investigate / Escalate from a written playbook, with the rule that decided it, the next steps and the Advanced Hunting (KQL) query an analyst would run |
| Deliver to service levels | Each alert shows its example SLA and how much of it is left |
| Endpoint and server health checks | **Device health**: stale signatures, inactive sensors, tamper protection off, unsupported OS, ASR rules only in audit |
| Support phishing / malware investigations, recommend remediation | **Phishing check**: paste an email (with headers) → verdict, the evidence for it, and the remediation steps |
| Regular security reports, documentation | **Weekly report**: a customer-ready report from the week's alerts and health, downloadable |
| Policy changes, containment | Shown as the recommended action per alert (isolate device, reset password, block sender), never executed |

## Honesty rules

- All companies, people, devices, alerts and emails are invented. Say so on screen.
- Alert titles and product names follow Microsoft Defender's public naming; the app does not connect to Defender.
- Decisions come from fixed, readable rules (`playbook.py`, `phishing.py`), not from an AI.
- Test answers are written per case **before** checking the rules against them. Misses are shown, not tuned away.
- SLA times are labelled "example service levels".

## PASS / FAIL checks

1. PASS if every critical/high alert without a confirmed automatic fix is escalated (0 misses) on the test set.
2. PASS if the playbook matches the written answer on ≥ 90% of test alerts, with every miss listed in the app.
3. PASS if the phishing check calls every phishing test email "Phishing" or "Suspicious" (0 phishing marked safe), and lists its false alarms.
4. PASS if every device-health finding names the device, the problem and the fix.
5. PASS if the weekly report's numbers match the queue's numbers exactly.
6. PASS if the app loads with no errors in light and dark mode, on a phone (390 px) and a desktop, with no sideways scrolling.
7. PASS if the answer is on the first screen: how many alerts to escalate now, to investigate, and closed.
