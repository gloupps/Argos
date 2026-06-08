# 🔍 Argos

> **⚠️ Actively under development — unstable, incomplete, broken in places.**  
> Designed to run **locally only**. Do not deploy in production.

> 🤖 Built through **Vibecoding with Claude (Anthropic)** — the AI writes most of the code, I steer, test, and break things.

---

## What is it?

Argos is a local **Cyber Threat Intelligence (CTI)** investigation platform for analysts. It lets you open a case, paste a list of IOCs (IPs, domains, URLs, file hashes), and in one click:

- **Enrich** them in parallel across a dozen external and internal threat intelligence sources
- **Correlate** them to discover pivot nodes (shared infrastructure, certificates, ASNs, sandbox behavior…)
- **Investigate** them against your SIEM (QRadar, Splunk, Elasticsearch) over a custom date range
- **Visualize** the entire graph interactively — right-click any node to enrich on demand

The goal is to replace the tab-juggling of manual IOC investigations with a single local tool, without depending on a commercial platform.

---

## How it works

```
[Create case] → [Auto-enrich] → [Correlate / pivot] → [SIEM investigation] → [Graph + export]
```

1. **Create a case** — from a raw IOC list, a public report URL, a STIX2 bundle file, an OpenCTI/MISP report URL, or an existing case.
2. **Enrichment** — Argos queries all configured sources in parallel (via `asyncio.gather`) and stores results locally in SQLite. Results stream back to the UI in real time over WebSocket.
3. **Correlation / Pivot** — modules surface links between IOCs: shared Shodan service fingerprints, VirusTotal network communications, common DNS records, MISP event overlap, TLS certificate pivots, etc. Pivot nodes are created automatically and shown on the graph.
4. **SIEM investigation** — send all (or selected) IOCs to QRadar (AQL), Splunk (SPL), or Elasticsearch (DSL), scoped to a date range, across configured log sources / indexes.
5. **Interactive graph** — Cytoscape.js renders root IOCs, pivot nodes, and pivoted IOCs. Nodes are color-coded by type. Hold & drag to manually link nodes. Right-click for on-demand enrichment.
6. **STIX2 export** — export the full case as a STIX2.1 bundle (indicators + relationships).

---

## Architecture

```
Flask app (main.py)
├── ___init___.py  
├── services/
│   ├── __init__.py
│   ├── routes.py           — HTTP endpoints + SocketIO events
│   ├── database.py         — SQLite layer (aiosqlite)
│   ├── job_manager.py
│   └── services.py         — Single dispatcher: routes all actions to the right module
├── modules/
│   ├── __init__.py         — One Python class per enrichment / SIEM source
│   └── module.py           — Base class (get_info, get_correlation, get_quotas, get_fields, settings_fields)
├── static/
│   ├── css/
│       └── argos-theme.css — Full dark + light mode theme (CSS vars, data-theme scoping)
│   ├── images/
│   └── js/
│       ├── app.js
│       ├── module.js
│       └── modules/        — Sidebar + settings rendering; auto-discovers registered modules
│           ├── modules.js         
│           ├── qualif.js          — Enrichment panel rendering, field coloring, _THEME_MAP
│           ├── graph.js           — Cytoscape.js graph
│           ├── siem.js            — SIEM investigation panel
│           ├── siem_instances.js  — QRadar / Splunk / ES log source / index config UI
│           ├── es_instances.js    — Elasticsearch enrichment instances UI
│           └── case.js / case_actions.js / …
└── templates/         — Jinja2 HTML
```

**Key design rules:**
- All actions go through a single `/api/run` endpoint, dispatched in `services.py`.
- Adding a Python module that extends `Module` is enough to auto-register it in the sidebar, settings, and enrichment panel — provided the frontend `_THEME_MAP`, coloring rules, and icon entries in `qualif.js` are also added.
- All credentials and instance configs are stored in the browser's `localStorage` via `SecretStore`. Nothing sensitive is written to the server.

---

## Modules

### External enrichment (API key required)

| Module | IOC types | Notes |
|---|---|---|
| **VirusTotal** | IP, domain, URL, hash | Detection ratios, network comms, sandbox, pivot via graph |
| **Shodan** | IP | Services, banners, CVEs, ASN, org, geo; TLS/fingerprint pivot |
| **Censys** | IP, domain | Host scan data, services, certificates, ASN pivot |
| **URLScan** | URL, domain | Screenshot, page structure, linked domains pivot |
| **ViewDNS** | IP, domain | Reverse DNS, IP history, domain history |
| **AbuseIPDB** | IP | Abuse confidence score, reports, ISP, usage type |
| **ThreatFox** | IP, domain, URL, hash | Malware families, tags, confidence; abuse.ch feed |
| **Hybrid Analysis** | hash, domain, URL | Sandbox analysis, threat score, network IoCs |
| **External MISP (multi-instance)** | IP, domain, URL, hash | Configurable N external MISP instances, each with its own URL + API key |

### Internal enrichment (self-hosted instance)

| Module | IOC types | Notes |
|---|---|---|
| **OpenCTI** | IP, domain, URL, hash | GraphQL API; extracts reports, labels, relations, scores |
| **MISP** | IP, domain, URL, hash | REST API; events, tags, threat levels, galaxy clusters |
| **Elasticsearch (enrichment)** | IP, domain, URL, hash | Configurable ES instances queried as an internal CTI data source |

### SIEM investigation

| Module | Query language | Notes |
|---|---|---|
| **QRadar** | AQL | Per log-source config; custom `search_field` per source; always runs events + flows (IPv4) + DNS (domain) in parallel |
| **Splunk** | SPL | Per-index config with individual auth; grouped SPL queries by IOC type; parallel execution |
| **Elasticsearch** | ES DSL | Per-index config; timestamp detection; output field selection |

All SIEM modules support a configurable date range (start / end), custom log sources / indexes, and output field selection. Results stream back to the UI in real time.

---

## Tech stack

| Layer | Technology |
|---|---|
| Backend | Python, Flask, Flask-SocketIO, aiosqlite, aiohttp |
| Frontend | Vanilla JS (ES modules), Tailwind CSS, Lucide icons |
| Graph | Cytoscape.js (cose layout) |
| Database | SQLite (local) |
| Real-time | WebSocket via Socket.IO |
| Credentials | Browser `localStorage` (SecretStore) |

---

## Installation

```bash
git clone https://github.com/gloupps/Argos.git
cd Argos

python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

pip install -r requirements.txt

python main.py
```

Open `http://localhost:5555`.

---

## Configuration

All configuration is done from the **Settings** panel in the UI — no config files to edit.

- **External modules** — paste your API key in the corresponding field.
- **Internal modules** (OpenCTI, MISP, Elasticsearch enrichment) — provide the instance URL + API key.
- **Multi-instance MISP / ES** — add as many instances as needed; each gets its own name, URL, and key.
- **SIEM** — configure log sources (QRadar), indexes (Splunk / Elasticsearch), date range, and per-source search fields.

Everything is stored in `localStorage`. Nothing is sent to or stored on the server beyond the current session data.

---

## Project status

- [x] Case creation (IOC list, URL, STIX2 file, OpenCTI/MISP report, existing case)
- [x] Parallel multi-source enrichment with real-time streaming
- [x] Correlation / pivot (VirusTotal, Shodan, Censys, URLScan, MISP, ThreatFox…)
- [x] Interactive Cytoscape graph (right-click enrich, manual edge creation)
- [x] STIX2 export
- [x] Multi-instance MISP and Elasticsearch enrichment
- [x] SIEM investigation — QRadar (AQL), Splunk (SPL), Elasticsearch (DSL)
- [x] Dark / light theme
- [ ] Full module documentation
- [ ] Plenty of other broken or missing things

---

## Warnings

- 🚧 **Work in progress** — internal API, DB schema, and UI may change without notice.
- 🏠 **Local only** — no authentication, no multi-user support, no endpoint hardening. Do not expose on a public network.
- 🤖 **Vibecoding** — most of the code is AI-generated by Claude. It works, but don't expect production-grade polish.

---

## Contributing

Personal / experimental project.

---

## License

MIT