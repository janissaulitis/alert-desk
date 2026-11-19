# Alert Desk

A morning at a managed endpoint security desk, for one invented customer (Baltic Freight SIA).
Alerts are triaged by a written playbook (close / investigate / escalate), phishing reports are checked by fixed rules,
devices get health checks, and the customer gets a weekly report.

- `data.py` – invented alerts, devices and emails, each with the answer a senior analyst would give (written first)
- `playbook.py` – triage rules, next steps, hunting queries (KQL), example service levels
- `phishing.py` – email checks: sender, authentication, links, attachments
- `health.py` – endpoint and server health checks
- `report.py` – weekly customer report
- `tests/` – the PASS/FAIL checks from `SPEC.md`

Results on the test cases: 38/40 alerts decided like the analyst, 0 of 16 escalations missed; 15/16 emails exact,
0 phishing let through, 0 false alarms; 38/38 devices right. Everything is invented. Run: `streamlit run app.py`
