# Sentinel

Sentinel is an agentic SOC copilot for first-pass alert triage. It takes a security alert, investigates the attached indicators with MCP tools, maps findings to MITRE ATT&CK, and returns a structured incident report with severity, recommended action, IOCs, analyst notes, and investigation steps.

It is built for demos, prototypes, and security workflows where you want to show how an LLM can reason over multiple enrichment sources instead of answering from a single prompt.

## Highlights

- Autonomous alert investigation loop powered by Anthropic + MCP
- FastAPI backend with both synchronous and streaming analysis endpoints
- Custom web UI for submitting alerts and watching the investigation unfold
- Tool-based enrichment for IPs, domains, hashes, WHOIS, and MITRE ATT&CK
- Structured JSON output suitable for analyst review or downstream automation
- Sample alerts included for C2, DNS beaconing, and malware execution scenarios

## How It Works

Sentinel follows a simple investigation pipeline:

1. Receive an alert payload
2. Extract indicators such as IPs, domains, and file hashes
3. Launch MCP servers that expose enrichment tools over stdio
4. Let Claude decide which tools to call and how to interpret the results
5. Cross-reference findings across threat intel and registration data
6. Map observed behavior to MITRE ATT&CK techniques
7. Return a structured incident report

## Example Output

The agent is instructed to produce a final report shaped like this:

```json
{
  "alert_id": "ALT-2024-001",
  "severity": "HIGH",
  "recommended_action": "ESCALATE",
  "summary": "Outbound traffic from an internal workstation reached infrastructure that appears consistent with command-and-control activity.",
  "iocs": [
    {
      "type": "ip",
      "value": "185.220.101.47",
      "malicious": true,
      "confidence": 0.96,
      "source": "VirusTotal",
      "details": "High malicious detections and suspicious hosting context"
    }
  ],
  "mitre_techniques": [
    {
      "technique_id": "T1071",
      "technique_name": "Application Layer Protocol",
      "tactic": "Command And Control",
      "description": "Adversaries may communicate using application layer protocols.",
      "confidence": 0.82
    }
  ],
  "analyst_notes": "The destination and domain both show suspicious characteristics across multiple tools.",
  "escalation_reason": "Potential active C2 communication from an internal endpoint.",
  "false_positive_indicators": [],
  "investigation_steps": [
    "Look up destination IP",
    "Check domain reputation",
    "Correlate with WHOIS",
    "Map to MITRE ATT&CK"
  ]
}
```

## Architecture

### API layer

- `app/main.py`
  Hosts the FastAPI app, serves the web UI, exposes REST and SSE endpoints, and performs a lightweight health check against Anthropic.

### Agent layer

- `app/agent.py`
  Runs the reasoning loop, starts MCP servers as subprocesses, exposes their tools to Claude, routes tool calls, and emits investigation events.

### Tool layer

- `servers/virustotal_server.py`
  IP, domain, and hash reputation lookups
- `servers/threatintel_server.py`
  AbuseIPDB and OTX-style enrichment
- `servers/whois_server.py`
  Domain and IP WHOIS lookups
- `servers/mitre_server.py`
  MITRE ATT&CK search against the Enterprise dataset

### UI layer

- `app/static/index.html`
  Browser-based interface for entering alerts, starting investigations, and watching the tool/reasoning stream in real time.

## Current Data Source Behavior

This matters if you are evaluating the project as a live SOC integration versus a demo:

- `ANTHROPIC_API_KEY` is required for the investigation agent
- `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, and `OTX_API_KEY` are recognized by the app, but those servers currently still return mock data
- `USE_LIVE_WHOIS=true` enables live domain WHOIS via `python-whois`
- MITRE ATT&CK data is loaded from `data/mitre_enterprise.json` and refreshed when stale

In practice, Sentinel already demonstrates the core agent architecture and tool-routing pattern, while some intel providers are still stubbed for safe local demos.

## Project Structure

```text
.
├── app/
│   ├── agent.py
│   ├── main.py
│   ├── models.py
│   └── static/index.html
├── servers/
│   ├── mitre_server.py
│   ├── threatintel_server.py
│   ├── virustotal_server.py
│   └── whois_server.py
├── data/
│   └── mitre_enterprise.json
├── sample_alerts/
│   ├── c2_communication.json
│   ├── dns_beacon.json
│   └── malware_execution.json
├── .env.example
├── mcp_config.json
├── requirements.txt
└── README.md
```

## Quickstart

### 1. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure environment variables

```bash
cp .env.example .env
```

Set at least:

```env
ANTHROPIC_API_KEY=your_anthropic_key
```

Optional variables:

```env
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
OTX_API_KEY=
USE_LIVE_WHOIS=false
ANTHROPIC_MODEL=claude-sonnet-4-6
```

### 4. Run the app

```bash
uvicorn app.main:app --reload
```

Open:

- UI: `http://127.0.0.1:8000/`
- Swagger docs: `http://127.0.0.1:8000/docs`
- Health check: `http://127.0.0.1:8000/health`

## API

### `POST /analyze`

Runs the full investigation and returns:

- the final incident report
- the full investigation trace
- the original alert ID

### `POST /analyze/stream`

Streams investigation events as Server-Sent Events.

Event types:

- `thinking`
- `tool_call`
- `tool_result`
- `report`
- `error`
- `done`

### `GET /health`

Checks whether the backend can make a minimal Anthropic request and returns `ok` or `degraded`.

## Sample Alert Payload

```json
{
  "alert_id": "ALT-2024-003",
  "event_type": "dns_beaconing",
  "source_ip": "10.0.3.22",
  "domain": "malware-c2.tk",
  "timestamp": "2024-01-17T22:05:33Z",
  "raw_log": "DNS query: malware-c2.tk (47 queries in 23 minutes, interval ~30s)",
  "additional_context": {
    "query_count": 47,
    "interval_seconds": 30,
    "host": "LAPTOP-HR-05",
    "user": "sarah.jones",
    "first_seen": "2024-01-17T21:42:00Z"
  }
}
```

## Try the Included Samples

Run a non-streaming investigation:

```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  --data @sample_alerts/dns_beacon.json
```

Run a streaming investigation:

```bash
curl -N -X POST http://127.0.0.1:8000/analyze/stream \
  -H "Content-Type: application/json" \
  --data @sample_alerts/c2_communication.json
```

## Security and Secrets

- `.env` is ignored by git and should never be committed
- `.env.example` is the safe template to publish
- Keep API keys scoped and rotatable
- If a secret is ever committed, rotate it immediately and rewrite history before exposing the repository

## Limitations

- Live VirusTotal, AbuseIPDB, and OTX integrations are not implemented yet
- There is no authentication or user/session isolation
- There is no persistent case store or analyst feedback system
- The app is an investigation copilot, not a production-ready automated response platform

## Roadmap

- Replace mock enrichments with live provider integrations
- Add tests for MCP routing, report parsing, and alert edge cases
- Persist investigations and support case review workflows
- Add SIEM/EDR ingestion connectors
- Export reports into ticketing or incident management systems

## Tech Stack

- Python
- FastAPI
- Anthropic SDK
- MCP Python SDK
- Pydantic
- Uvicorn
- STIX2
- Vanilla HTML/CSS/JavaScript

## License

No license is currently included. Add a `LICENSE` file before broad public reuse if you want to define usage rights clearly.
