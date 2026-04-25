<div align="center">

# SOCrates

**Autonomous SOC Analyst · Claude + MCP**

*Investigate security alerts. Map MITRE ATT&CK techniques. File structured incident briefs. All in real time.*

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Anthropic](https://img.shields.io/badge/Claude-Sonnet-CC785C?style=flat-square)](https://anthropic.com)
[![MCP](https://img.shields.io/badge/MCP-1.2-6B46C1?style=flat-square)](https://modelcontextprotocol.io)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=flat-square)](LICENSE)

</div>

---

## Overview

SOCrates is an agentic security operations analyst that investigates alerts the way a human L1 analyst would — but autonomously. Drop in an alert payload, and SOCrates:

1. Extracts every indicator (IPs, domains, file hashes)
2. Calls specialized MCP tools to enrich each one across multiple threat intel sources
3. Cross-references findings, spots contradictions, and reasons about context
4. Maps observed TTPs to the MITRE ATT&CK framework
5. Files a structured incident brief with severity, recommended action, IOCs, and analyst notes — streamed to the UI in real time

The key idea: the agent doesn't just look things up. It *reasons* across tool outputs the same way a trained analyst does, surfacing *why* something is suspicious rather than just flagging a single score.

---

## Screenshot

> **To add:** take a screenshot of the UI after a completed investigation, save it as `assets/screenshot.png`, and uncomment the line below.

<!--
![SOCrates UI — Incident Brief](assets/screenshot.png)
-->

*Recommended shot: the three-column view with a CRITICAL severity brief on the right, the live cognitive feed streaming in the center, and the C2 Beacon scenario loaded on the left.*

---

## Demo

> **To add:** record a 30–45 second walkthrough (select scenario → Investigate → watch stream → brief auto-files), export as GIF, save as `assets/demo.gif`, and uncomment the line below.

<!--
![SOCrates — Live Investigation Demo](assets/demo.gif)
-->

*Suggested flow: C2 Beacon → Investigate → tool calls stream in → ESCALATE brief appears on the right.*

---

## How It Works

```
                   ┌──────────────────────────────────────────────┐
                   │              SOCRATES AGENT LOOP              │
                   └──────────────────────────────────────────────┘

  Alert JSON          ┌─────────────┐    Tool calls    ┌──────────────────┐
  ──────────────────► │             │ ───────────────► │   MCP Servers    │
                      │   Claude    │                  │                  │
  SSE event stream    │   Sonnet    │ ◄─── Results ─── │ · VirusTotal     │
  ◄────────────────── │             │                  │ · ThreatIntel    │
                      └─────────────┘                  │ · WHOIS          │
                            │                          │ · MITRE ATT&CK   │
                            ▼                          └──────────────────┘
                     Structured Report
                     (severity · IOCs
                      MITRE · action)
```

The agent runs in a self-directed loop — up to 15 reasoning turns — calling whichever tools it decides are relevant before synthesizing a final brief. No fixed pipeline, no hardcoded sequence.

---

## MCP Tool Surface

| Server | Tools | Data Source |
|--------|-------|-------------|
| `virustotal_server.py` | `virustotal_ip_lookup`, `virustotal_domain_lookup`, `virustotal_hash_lookup` | VirusTotal v3 API |
| `threatintel_server.py` | `abuseipdb_lookup`, `otx_lookup` | AbuseIPDB · OTX AlienVault |
| `whois_server.py` | `whois_domain`, `whois_ip` | python-whois · ipwhois RDAP |
| `mitre_server.py` | `mitre_search`, `mitre_get_technique` | MITRE ATT&CK Enterprise (STIX) |

All servers speak the MCP stdio transport and call live upstream APIs — no mock data. The agent routes each tool call to the correct server at runtime.

---

## Quickstart

### Prerequisites

- Python 3.11+
- An Anthropic API key → [console.anthropic.com](https://console.anthropic.com)

### 1 · Clone and create a virtual environment

```bash
git clone https://github.com/visheshshah/Sentinel.git SOCrates
cd SOCrates
python3 -m venv .venv && source .venv/bin/activate
```

### 2 · Install dependencies

```bash
pip install -r requirements.txt
```

### 3 · Configure environment

```bash
cp .env.example .env
```

Open `.env` and set your keys:

```env
# Required
ANTHROPIC_API_KEY=sk-ant-...

# Threat intel — required for live investigations
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
OTX_API_KEY=

# Override model if needed (default: claude-sonnet-4-6)
ANTHROPIC_MODEL=claude-sonnet-4-6
```

> `.env` is git-ignored. Never commit it. WHOIS lookups run live without any extra configuration.

### 4 · Start the server

```bash
uvicorn app.main:app --reload
```

| Endpoint | URL |
|----------|-----|
| Web UI | http://127.0.0.1:8000/ |
| Swagger docs | http://127.0.0.1:8000/docs |
| Readiness check | http://127.0.0.1:8000/health |
| Liveness check | http://127.0.0.1:8000/health/live |

### 5 · Run your first investigation

Select one of the three built-in scenarios in the UI, or hit the API directly:

```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  --data @sample_alerts/c2_communication.json | jq '.report.severity, .report.recommended_action'
```

---

## API Reference

### `POST /analyze`

Synchronous. Runs the full investigation and returns when complete.

**Request body:**

```json
{
  "alert_id": "ALT-2024-001",
  "event_type": "outbound_connection",
  "source_ip": "10.0.1.45",
  "destination_ip": "185.220.101.47",
  "domain": "cmd.evil-domain.ru",
  "timestamp": "2024-01-15T14:23:11Z",
  "raw_log": "Jan 15 14:23:11 firewall PERMIT src=10.0.1.45 dst=185.220.101.47 dport=4444",
  "additional_context": { "user": "john.doe", "host": "WORKSTATION-042" },
  "model": "claude-sonnet-4-6"
}
```

**Response:**

```json
{
  "alert_id": "ALT-2024-001",
  "report": {
    "severity": "HIGH",
    "recommended_action": "ESCALATE",
    "summary": "...",
    "iocs": [...],
    "mitre_techniques": [...],
    "analyst_notes": "...",
    "escalation_reason": "...",
    "false_positive_indicators": [],
    "investigation_steps": [...]
  },
  "investigation_trace": [...]
}
```

---

### `POST /analyze/stream`

Streaming. Returns investigation events as Server-Sent Events as they happen.

| Event type | When | Key fields |
|------------|------|------------|
| `thinking` | Agent reasoning step | `content` |
| `tool_call` | Before a tool is invoked | `tool_name`, `tool_input` |
| `tool_result` | After a tool returns | `tool_name`, `content` |
| `report` | Investigation complete | `content` (JSON string) |
| `error` | Unrecoverable failure | `content` |
| `done` | Stream closed | — |

```bash
curl -N -X POST http://127.0.0.1:8000/analyze/stream \
  -H "Content-Type: application/json" \
  --data @sample_alerts/dns_beacon.json
```

---

### `GET /health` · `GET /health/live`

`/health` is a readiness probe — verifies Anthropic is reachable. Returns 503 when degraded so load balancers will pull traffic.
`/health/live` is a fast liveness probe with no external calls.

```json
{ "status": "ok", "model": "claude-sonnet-4-6" }
```

---

## Included Scenarios

Three realistic alert payloads are in `sample_alerts/`:

| File | Scenario | Indicators |
|------|----------|------------|
| `c2_communication.json` | Internal host beaconing to port 4444 on a known-bad IP | IP, domain |
| `malware_execution.json` | Word document spawning a temp-path executable | IP, MD5 hash |
| `dns_beacon.json` | 47 DNS queries at 30-second intervals to a `.tk` domain | domain |

---

## Project Structure

```
SOCrates/
├── app/
│   ├── main.py               # FastAPI app — REST + SSE endpoints + UI serving
│   ├── agent.py              # Agentic loop — MCP orchestration + Claude
│   ├── models.py             # Pydantic models (Alert, IncidentReport, AgentEvent)
│   └── static/
│       └── index.html        # Browser UI (single-file, no build step)
├── servers/
│   ├── virustotal_server.py  # MCP server — VT reputation lookups
│   ├── threatintel_server.py # MCP server — AbuseIPDB + OTX enrichment
│   ├── whois_server.py       # MCP server — domain + IP WHOIS (RDAP)
│   └── mitre_server.py       # MCP server — MITRE ATT&CK Enterprise
├── data/
│   └── mitre_enterprise.json # Auto-refreshed ATT&CK dataset
├── sample_alerts/
│   ├── c2_communication.json
│   ├── dns_beacon.json
│   └── malware_execution.json
├── .env.example              # Safe template — commit this, not .env
├── .gitignore                # .env and .venv excluded
├── mcp_config.json
└── requirements.txt
```

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Agent reasoning | Anthropic Claude (Sonnet 4.6, Opus 4.6/4.7, Haiku 4.5) via `anthropic` SDK |
| Tool protocol | Model Context Protocol (MCP) — stdio transport |
| Backend | FastAPI + Uvicorn |
| Streaming | Server-Sent Events (SSE) |
| Data models | Pydantic v2 |
| Threat intelligence | VirusTotal · AbuseIPDB · OTX · MITRE ATT&CK (STIX2) |
| Frontend | Vanilla HTML / CSS / JS — no build step |

---

## Security Notes

- `.env` is git-ignored — API keys never enter version control
- `.env.example` is the committed safe template
- If a secret is ever accidentally committed: rotate it immediately, then use [`git filter-repo`](https://github.com/newren/git-filter-repo) or BFG Repo Cleaner to scrub history before making the repository public

---

## Roadmap

- [x] Live VirusTotal, AbuseIPDB, OTX, and WHOIS integrations
- [x] Multi-model selection in UI (Sonnet · Opus · Haiku)
- [ ] Persistent case store with analyst feedback loop
- [ ] SIEM / EDR ingestion connectors (webhook + syslog)
- [ ] Report export to PDF and ticketing systems (Jira, ServiceNow)
- [ ] Multi-alert correlation and campaign detection
- [ ] Auth layer for multi-analyst deployments

---

## License

MIT — see [LICENSE](LICENSE)
