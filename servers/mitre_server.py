"""
MCP Server: MITRE ATT&CK
Downloads and caches the MITRE ATT&CK Enterprise STIX bundle.
Provides technique search by keyword, tactic, or technique ID.
Cache lives at data/mitre_enterprise.json — refreshed if older than 7 days.
"""

import asyncio
import json
import os
import sys
import time
from pathlib import Path
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

# Path resolution: servers/ sits one level below project root
PROJECT_ROOT = Path(__file__).parent.parent
CACHE_PATH = PROJECT_ROOT / "data" / "mitre_enterprise.json"
STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CACHE_TTL_SECONDS = 7 * 24 * 3600  # 7 days


def _load_or_fetch_stix() -> dict:
    """Load STIX bundle from cache, fetching from MITRE GitHub if stale."""
    if CACHE_PATH.exists():
        age = time.time() - CACHE_PATH.stat().st_mtime
        if age < CACHE_TTL_SECONDS:
            with open(CACHE_PATH) as f:
                return json.load(f)
        print(f"[mitre_server] Cache is {age/3600:.1f}h old — refreshing", file=sys.stderr)
    else:
        print("[mitre_server] No cache found — downloading MITRE ATT&CK STIX bundle", file=sys.stderr)

    import urllib.request
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(STIX_URL, timeout=30) as resp:
        data = json.loads(resp.read())
    with open(CACHE_PATH, "w") as f:
        json.dump(data, f)
    print(f"[mitre_server] Saved STIX bundle to {CACHE_PATH}", file=sys.stderr)
    return data


def _parse_techniques(stix_bundle: dict) -> list[dict]:
    """Extract attack-pattern objects (techniques/sub-techniques) from the STIX bundle."""
    techniques = []
    for obj in stix_bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue

        # Extract technique ID (e.g., T1059.001)
        tech_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id")
                break
        if not tech_id:
            continue

        # Extract tactic(s)
        tactics = [
            phase["phase_name"].replace("-", " ").title()
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        techniques.append({
            "id": tech_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", "")[:500],  # truncate for embedding
            "tactics": tactics,
            "platforms": obj.get("x_mitre_platforms", []),
            "detection": obj.get("x_mitre_detection", "")[:300],
            "is_subtechnique": "." in tech_id,
        })
    return techniques


# Global technique index — loaded once at startup
_TECHNIQUES: list[dict] = []


def _ensure_loaded():
    global _TECHNIQUES
    if not _TECHNIQUES:
        bundle = _load_or_fetch_stix()
        _TECHNIQUES = _parse_techniques(bundle)
        print(f"[mitre_server] Loaded {len(_TECHNIQUES)} techniques", file=sys.stderr)


def _search_techniques(
    keywords: list[str] | None = None,
    tactic: str | None = None,
    technique_id: str | None = None,
    limit: int = 5,
) -> list[dict]:
    _ensure_loaded()
    results = []

    for tech in _TECHNIQUES:
        # Exact ID match takes priority
        if technique_id:
            if tech["id"].upper() == technique_id.upper():
                return [tech]
            continue

        score = 0

        # Tactic filter
        if tactic:
            tactic_match = any(tactic.lower() in t.lower() for t in tech["tactics"])
            if not tactic_match:
                continue

        # Keyword scoring
        if keywords:
            searchable = (
                tech["name"] + " " + tech["description"] + " " + " ".join(tech["tactics"])
            ).lower()
            for kw in keywords:
                if kw.lower() in searchable:
                    # Name matches score higher
                    score += 3 if kw.lower() in tech["name"].lower() else 1

            if score == 0:
                continue

        results.append((score, tech))

    results.sort(key=lambda x: x[0], reverse=True)
    return [t for _, t in results[:limit]]


app = Server("mitre-attack")


@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="mitre_search",
            description=(
                "Search the MITRE ATT&CK Enterprise knowledge base for techniques matching "
                "given keywords, a tactic name, or a specific technique ID (e.g., T1059). "
                "Returns technique ID, name, tactic, description, detection guidance, and platforms."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "keywords": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Keywords to search for in technique name and description. "
                            "Example: ['powershell', 'execution'] or ['lateral movement', 'smb']"
                        ),
                    },
                    "tactic": {
                        "type": "string",
                        "description": (
                            "Filter by ATT&CK tactic. "
                            "Options: Initial Access, Execution, Persistence, Privilege Escalation, "
                            "Defense Evasion, Credential Access, Discovery, Lateral Movement, "
                            "Collection, Command And Control, Exfiltration, Impact"
                        ),
                    },
                    "technique_id": {
                        "type": "string",
                        "description": "Exact technique ID to look up, e.g., T1059 or T1059.001",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of results to return (default 5, max 10)",
                        "default": 5,
                    },
                },
            },
        ),
        types.Tool(
            name="mitre_get_technique",
            description="Get full details for a specific MITRE ATT&CK technique by ID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "technique_id": {
                        "type": "string",
                        "description": "Technique ID, e.g., T1059.001",
                    }
                },
                "required": ["technique_id"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    try:
        if name == "mitre_search":
            results = _search_techniques(
                keywords=arguments.get("keywords"),
                tactic=arguments.get("tactic"),
                technique_id=arguments.get("technique_id"),
                limit=min(arguments.get("limit", 5), 10),
            )
            result = {
                "count": len(results),
                "techniques": results,
            }

        elif name == "mitre_get_technique":
            matches = _search_techniques(technique_id=arguments["technique_id"])
            if matches:
                result = matches[0]
            else:
                result = {"error": f"Technique {arguments['technique_id']} not found"}

        else:
            result = {"error": f"Unknown tool: {name}"}

    except Exception as e:
        result = {"error": str(e)}

    return [types.TextContent(type="text", text=json.dumps(result, indent=2))]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
