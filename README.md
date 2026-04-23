<div align="center">

# Sentinel

**Autonomous SOC Analyst Copilot · Claude + MCP**

*Investigate security alerts. Map MITRE ATT&CK techniques. File structured incident briefs. All in real time.*

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Anthropic](https://img.shields.io/badge/Claude-Sonnet-CC785C?style=flat-square)](https://anthropic.com)
[![MCP](https://img.shields.io/badge/MCP-1.2-6B46C1?style=flat-square)](https://modelcontextprotocol.io)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=flat-square)](LICENSE)

</div>

---

## Overview

Sentinel is an agentic security operations copilot that investigates alerts the way a human L1 analyst would — but autonomously. Drop in an alert payload, and Sentinel:

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
![Sentinel UI — Incident Brief](assets/screenshot.png)
-->

*Recommended shot: the three-column view with a CRITICAL severity brief on the right, the live cognitive feed streaming in the center, and the C2 Beacon scenario loaded on the left.*

---

## Demo

> **To add:** record a 30–45 second walkthrough (select scenario → Initiate → watch stream → brief auto-files), export as GIF, save as `assets/demo.gif`, and uncomment the line below.

<!--
![Sentinel — Live Investigation Demo](assets/demo.gif)
-->

*Suggested flow: C2 Beacon → Initiate Investigation → tool calls stream in → ESCALATE brief appears on the right.*

---

## How It Works

```
                   ┌──────────────────────────────────────────────┐
                   │              SENTINEL AGENT LOOP              │
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
| `virustotal_server.py` | `lookup_ip`, `lookup_domain`, `lookup_hash` | VirusTotal API |
| `threatintel_server.py` | `check_ip_abuse`, `search_otx_pulses` | AbuseIPDB · OTX |
| `whois_server.py` | `whois_domain`, `whois_ip` | WHOIS (live or mock) |
| `mitre_server.py` | `search_techniques`, `get_technique_by_id` | MITRE ATT&CK Enterprise |

All servers speak the MCP stdio transport. The agent routes each tool call to the correct server at runtime — no hardcoded dispatch.

---

## Quickstart

### Prerequisites

- Python 3.11+
- An Anthropic API key → [console.anthropic.com](https://console.anthropic.com)

### 1 · Clone and create a virtual environment

```bash
git clone https://github.com/visheshshah/Sentinel.git
cd Sentinel
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

# Optional — leave blank to use realistic mock data
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
OTX_API_KEY=

# Set to "true" for live WHOIS lookups
USE_LIVE_WHOIS=false

# Override model if needed (default: claude-sonnet-4-6)
ANTHROPIC_MODEL=claude-sonnet-4-6
```

> `.env` is git-ignored. Never commit it. Only `ANTHROPIC_API_KEY` is required to run Sentinel end-to-end.

### 4 · Start the server

```bash
uvicorn app.main:app --reload
```

| Endpoint | URL |
|----------|-----|
| Web UI | http://127.0.0.1:8000/ |
| Swagger docs | http://127.0.0.1:8000/docs |
| Health check | http://127.0.0.1:8000/health |

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
  "additional_context": { "user": "john.doe", "host": "WORKSTATION-042" }
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

### `GET /health`

Returns system status and whether Anthropic is reachable.

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
Sentinel/
├── app/
│   ├── main.py               # FastAPI app — REST + SSE endpoints + UI serving
│   ├── agent.py              # Agentic loop — MCP orchestration + Claude
│   ├── models.py             # Pydantic models (Alert, IncidentReport, AgentEvent)
│   └── static/
│       └── index.html        # Browser UI (single-file, no build step)
├── servers/
│   ├── virustotal_server.py  # MCP server — VT reputation lookups
│   ├── threatintel_server.py # MCP server — AbuseIPDB + OTX enrichment
│   ├── whois_server.py       # MCP server — domain + IP WHOIS
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
| Agent reasoning | Anthropic Claude Sonnet via `anthropic` SDK |
| Tool protocol | Model Context Protocol (MCP) — stdio transport |
| Backend | FastAPI + Uvicorn |
| Streaming | Server-Sent Events (SSE) |
| Data models | Pydantic v2 |
| Threat intelligence | MITRE ATT&CK via STIX2 |
| Frontend | Vanilla HTML / CSS / JS — no build step |

---

## Security Notes

- `.env` is git-ignored — API keys never enter version control
- `.env.example` is the committed safe template
- If a secret is ever accidentally committed: rotate it immediately, then use [`git filter-repo`](https://github.com/newren/git-filter-repo) or BFG Repo Cleaner to scrub history before making the repository public

---

## Roadmap

- [ ] Live VirusTotal, AbuseIPDB, and OTX integrations (replace mock data)
- [ ] Persistent case store with analyst feedback loop
- [ ] SIEM / EDR ingestion connectors (webhook + syslog)
- [ ] Report export to PDF and ticketing systems (Jira, ServiceNow)
- [ ] Multi-alert correlation and campaign detection
- [ ] Auth layer for multi-analyst deployments

---

## License

MIT — see [LICENSE](LICENSE)
