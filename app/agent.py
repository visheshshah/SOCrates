"""
Agentic SOC Copilot — core reasoning loop.

Bridges MCP servers ↔ Anthropic API:
  1. Launches each MCP server as a subprocess (stdio transport)
  2. Lists available tools from all servers
  3. Feeds alert + tools to Claude
  4. Routes tool calls back to the correct server
  5. Streams events (thinking, tool_call, tool_result, report) to the caller
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import AsyncGenerator

import anthropic
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from app.models import Alert, AgentEvent

PROJECT_ROOT = Path(__file__).parent.parent
SERVERS_DIR = PROJECT_ROOT / "servers"

# One entry per MCP server
MCP_SERVERS = [
    StdioServerParameters(
        command=sys.executable,
        args=[str(SERVERS_DIR / "virustotal_server.py")],
        env=None,
    ),
    StdioServerParameters(
        command=sys.executable,
        args=[str(SERVERS_DIR / "whois_server.py")],
        env=None,
    ),
    StdioServerParameters(
        command=sys.executable,
        args=[str(SERVERS_DIR / "threatintel_server.py")],
        env=None,
    ),
    StdioServerParameters(
        command=sys.executable,
        args=[str(SERVERS_DIR / "mitre_server.py")],
        env=None,
    ),
]

MODEL = "claude-sonnet-4-6"
MAX_TOKENS = 8192

SYSTEM_PROMPT = """You are an autonomous SOC L1 analyst copilot. Your job is to investigate security alerts and produce structured incident reports.

Given an alert, you will:
1. Decide which indicators (IPs, domains, hashes) need investigation
2. Call the appropriate tools to gather threat intelligence
3. Map findings to MITRE ATT&CK techniques
4. Synthesize everything into a structured incident report

Investigation principles:
- Always check ALL indicators present in the alert (source IP, destination IP, domain, hash)
- Cross-reference findings across multiple sources (VT + AbuseIPDB + OTX)
- A high VT detection count + AbuseIPDB reports + OTX pulses = strong malicious signal
- Newly registered domains (< 90 days) with privacy protection are inherently suspicious
- Map observed behavior to the most specific MITRE technique possible
- Consider context: internal IPs hitting known C2 = critical; external scanner = low

Severity thresholds:
- CRITICAL: Active C2 communication, confirmed malware execution, data exfiltration
- HIGH: Known malicious infrastructure, active exploitation attempt
- MEDIUM: Suspicious indicators with partial confirmation
- LOW: Weak signals, likely noise or scanner traffic

Output format — end your analysis with a JSON block wrapped in ```json ... ``` containing:
{
  "alert_id": "...",
  "severity": "LOW|MEDIUM|HIGH|CRITICAL",
  "recommended_action": "CLOSE|MONITOR|ESCALATE|BLOCK",
  "summary": "2-3 sentence executive summary",
  "iocs": [{"type": "ip|domain|hash", "value": "...", "malicious": true, "confidence": 0.95, "source": "VirusTotal", "details": "..."}],
  "mitre_techniques": [{"technique_id": "T1...", "technique_name": "...", "tactic": "...", "description": "...", "confidence": 0.8}],
  "analyst_notes": "Detailed findings and reasoning",
  "escalation_reason": "Why this needs human review (if escalating)",
  "false_positive_indicators": ["list of reasons it might be FP"],
  "investigation_steps": ["step 1", "step 2", ...]
}"""


def _build_alert_message(alert: Alert) -> str:
    return f"""Investigate the following security alert:

```json
{alert.model_dump_json(indent=2)}
```

Begin your investigation. Call tools as needed to gather evidence before writing your report."""


async def _connect_all_servers() -> tuple[list[tuple], dict[str, ClientSession], list[dict]]:
    """
    Connect to all MCP servers and collect their tool definitions.
    Returns (contexts, tool_to_session_map, anthropic_tools).
    Each context entry is a (stdio_client_ctx, ClientSession) tuple for cleanup.
    """
    tool_to_session: dict[str, ClientSession] = {}
    anthropic_tools = []
    contexts: list[tuple] = []

    try:
        for server_params in MCP_SERVERS:
            ctx = stdio_client(server_params)
            read, write = await ctx.__aenter__()
            session = ClientSession(read, write)
            await session.__aenter__()
            await session.initialize()

            tools_result = await session.list_tools()
            for tool in tools_result.tools:
                tool_to_session[tool.name] = session
                anthropic_tools.append({
                    "name": tool.name,
                    "description": tool.description,
                    "input_schema": tool.inputSchema,
                })

            contexts.append((ctx, session))
    except Exception:
        # Clean up any servers that connected before the failure
        for ctx, session in contexts:
            try:
                await session.__aexit__(None, None, None)
                await ctx.__aexit__(None, None, None)
            except Exception:
                pass
        raise

    return contexts, tool_to_session, anthropic_tools


async def run_investigation(alert: Alert) -> AsyncGenerator[AgentEvent, None]:
    """
    Main agentic loop. Yields AgentEvent objects as the investigation progresses.
    Connects to MCP servers, runs Claude's tool-use loop, streams events.
    """
    client = anthropic.AsyncAnthropic()
    contexts = []

    try:
        yield AgentEvent(type="thinking", content="Connecting to MCP servers...")

        contexts, tool_to_session, anthropic_tools = await _connect_all_servers()

        yield AgentEvent(
            type="thinking",
            content=f"Connected. {len(anthropic_tools)} tools available: {', '.join(t['name'] for t in anthropic_tools)}",
        )

        messages = [{"role": "user", "content": _build_alert_message(alert)}]

        # Agentic loop — continues until Claude stops calling tools
        iteration = 0
        max_iterations = 15  # safety ceiling

        while iteration < max_iterations:
            iteration += 1

            yield AgentEvent(type="thinking", content=f"Reasoning (turn {iteration})...")

            response = await client.messages.create(
                model=MODEL,
                max_tokens=MAX_TOKENS,
                system=SYSTEM_PROMPT,
                tools=anthropic_tools,
                messages=messages,
            )

            # Build the full assistant message content list
            assistant_content = []
            tool_results = []  # (tool_use_id, result_text) pairs

            for block in response.content:
                if block.type == "text":
                    text = block.text.strip()
                    if text:
                        yield AgentEvent(type="thinking", content=text)
                    assistant_content.append({"type": "text", "text": block.text})

                elif block.type == "tool_use":
                    yield AgentEvent(
                        type="tool_call",
                        content=f"Calling {block.name}",
                        tool_name=block.name,
                        tool_input=block.input,
                    )

                    assistant_content.append({
                        "type": "tool_use",
                        "id": block.id,
                        "name": block.name,
                        "input": block.input,
                    })

                    # Route tool call to the correct MCP server
                    session = tool_to_session.get(block.name)
                    if not session:
                        tool_result_text = json.dumps({"error": f"No server handles tool '{block.name}'"})
                    else:
                        try:
                            mcp_result = await session.call_tool(block.name, arguments=block.input)
                            tool_result_text = "\n".join(
                                c.text for c in mcp_result.content if hasattr(c, "text")
                            )
                        except Exception as e:
                            tool_result_text = json.dumps({"error": str(e)})

                    yield AgentEvent(
                        type="tool_result",
                        content=tool_result_text,
                        tool_name=block.name,
                    )
                    tool_results.append((block.id, tool_result_text))

            # Append assistant turn + all tool results in one user message
            if assistant_content:
                messages.append({"role": "assistant", "content": assistant_content})

            if tool_results:
                messages.append({
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": tool_use_id,
                            "content": result_text,
                        }
                        for tool_use_id, result_text in tool_results
                    ],
                })

            # No more tool calls — Claude is done or hit token limit
            if response.stop_reason in ("end_turn", "max_tokens"):
                final_text = " ".join(
                    b.text for b in response.content if b.type == "text"
                )
                if response.stop_reason == "max_tokens":
                    final_text += "\n\n[Response truncated due to max_tokens limit]"
                report_json = _extract_json_report(final_text)
                yield AgentEvent(
                    type="report",
                    content=json.dumps(report_json) if report_json else final_text,
                )
                break

    except Exception as e:
        yield AgentEvent(type="error", content=f"Investigation failed: {str(e)}")

    finally:
        # Clean up all MCP sessions
        for ctx, session in contexts:
            try:
                await session.__aexit__(None, None, None)
                await ctx.__aexit__(None, None, None)
            except Exception:
                pass


def _extract_json_report(text: str) -> dict | None:
    """Extract the JSON incident report from Claude's final response."""
    import re
    pattern = r"```json\s*([\s\S]*?)\s*```"
    match = re.search(pattern, text)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    # Fallback: try parsing the entire text
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None
