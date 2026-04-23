"""
FastAPI application — SOC Copilot API.
Endpoints:
  POST /analyze        — submit an alert, get back a full investigation (non-streaming)
  POST /analyze/stream — submit an alert, receive SSE stream of agent events
  GET  /               — serves the web UI
"""

import json
import os
from pathlib import Path

import anthropic
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse

load_dotenv(Path(__file__).parent.parent / ".env")

from app.agent import run_investigation
from app.models import Alert, AgentEvent

app = FastAPI(
    title="Agentic SOC Copilot",
    description="AI-powered security alert triage using Claude + MCP tools",
    version="0.1.0",
)

STATIC_DIR = Path(__file__).parent / "static"


@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    html_path = STATIC_DIR / "index.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="UI not found")
    return HTMLResponse(content=html_path.read_text())


@app.post("/analyze/stream")
async def analyze_stream(alert: Alert):
    """
    Submit an alert and receive a Server-Sent Events stream of agent events.
    Each event is a JSON-encoded AgentEvent:
      { "type": "thinking"|"tool_call"|"tool_result"|"report"|"error", "content": "...", ... }
    """

    async def event_generator():
        try:
            async for event in run_investigation(alert):
                data = event.model_dump_json()
                yield f"data: {data}\n\n"
        except Exception as e:
            error = AgentEvent(type="error", content=str(e))
            yield f"data: {error.model_dump_json()}\n\n"
        finally:
            yield "data: {\"type\": \"done\", \"content\": \"\"}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering for SSE
        },
    )


@app.post("/analyze")
async def analyze(alert: Alert):
    """
    Submit an alert and receive the complete investigation result (non-streaming).
    Returns all events collected during the investigation.
    """
    events = []
    report = None
    last_error = None

    async for event in run_investigation(alert):
        events.append(event.model_dump())
        if event.type == "report":
            try:
                report = json.loads(event.content)
            except json.JSONDecodeError:
                report = {"raw": event.content}
        elif event.type == "error":
            last_error = event.content

    if report is None and last_error is not None:
        raise HTTPException(
            status_code=502,
            detail={
                "alert_id": alert.alert_id,
                "error": last_error,
                "investigation_trace": events,
            },
        )

    if report is None:
        raise HTTPException(
            status_code=500,
            detail={
                "alert_id": alert.alert_id,
                "error": "Investigation completed without producing a report",
                "investigation_trace": events,
            },
        )

    return {
        "alert_id": alert.alert_id,
        "report": report,
        "investigation_trace": events,
    }


@app.get("/health")
async def health():
    model = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return {"status": "degraded", "model": model, "error": "ANTHROPIC_API_KEY not set"}
    try:
        client = anthropic.AsyncAnthropic()
        await client.messages.create(
            model=model,
            max_tokens=1,
            messages=[{"role": "user", "content": "ping"}],
        )
        return {"status": "ok", "model": model}
    except Exception as e:
        return {"status": "degraded", "model": model, "error": str(e)}
