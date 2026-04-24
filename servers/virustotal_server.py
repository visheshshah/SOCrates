"""
MCP Server: VirusTotal
Provides IP, domain, and file hash reputation lookups via the VirusTotal v3 API.
Requires VIRUSTOTAL_API_KEY in environment. No mock fallback when key is present.
"""

import asyncio
import json
import os
import sys
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types
import httpx

VT_BASE = "https://www.virustotal.com/api/v3"

app = Server("virustotal")


def _api_key() -> str:
    key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not key:
        raise RuntimeError("VIRUSTOTAL_API_KEY is not set")
    return key


def _headers() -> dict:
    return {"x-apikey": _api_key(), "Accept": "application/json"}


def _parse_stats(attrs: dict) -> dict:
    stats = attrs.get("last_analysis_stats", {})
    return {
        "malicious":  stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless":   stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
    }


@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="virustotal_ip_lookup",
            description=(
                "Look up an IP address on VirusTotal to check its reputation, "
                "detection count, country of origin, ASN, and associated tags."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "IPv4 or IPv6 address to look up"}
                },
                "required": ["ip"],
            },
        ),
        types.Tool(
            name="virustotal_hash_lookup",
            description=(
                "Look up a file hash (MD5, SHA1, or SHA256) on VirusTotal "
                "to check detection ratio, file type, known names, and tags."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "hash": {"type": "string", "description": "File hash (MD5/SHA1/SHA256)"}
                },
                "required": ["hash"],
            },
        ),
        types.Tool(
            name="virustotal_domain_lookup",
            description=(
                "Look up a domain on VirusTotal to check its reputation, "
                "detection count, registrar, and any associated malware tags."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Domain name to look up"}
                },
                "required": ["domain"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    try:
        headers = _headers()
    except RuntimeError as e:
        return [types.TextContent(type="text", text=json.dumps({"error": str(e)}))]

    async with httpx.AsyncClient(timeout=20) as client:
        try:
            if name == "virustotal_ip_lookup":
                ip = arguments["ip"]
                resp = await client.get(f"{VT_BASE}/ip_addresses/{ip}", headers=headers)
                resp.raise_for_status()
                attrs = resp.json()["data"]["attributes"]
                result = {
                    "ip": ip,
                    "mock": False,
                    **_parse_stats(attrs),
                    "country":           attrs.get("country", ""),
                    "asn":               attrs.get("asn", ""),
                    "as_owner":          attrs.get("as_owner", ""),
                    "last_analysis_date": attrs.get("last_modification_date", ""),
                    "tags":              attrs.get("tags", []),
                    "reputation":        attrs.get("reputation", 0),
                    "network":           attrs.get("network", ""),
                }

            elif name == "virustotal_hash_lookup":
                h = arguments["hash"]
                resp = await client.get(f"{VT_BASE}/files/{h}", headers=headers)
                resp.raise_for_status()
                attrs = resp.json()["data"]["attributes"]
                result = {
                    "hash": h,
                    "mock": False,
                    **_parse_stats(attrs),
                    "type_description":  attrs.get("type_description", ""),
                    "size":              attrs.get("size", 0),
                    "names":             attrs.get("names", [])[:10],
                    "last_analysis_date": attrs.get("last_analysis_date", ""),
                    "tags":              attrs.get("tags", []),
                    "reputation":        attrs.get("reputation", 0),
                    "magic":             attrs.get("magic", ""),
                    "sha256":            attrs.get("sha256", ""),
                    "md5":               attrs.get("md5", ""),
                }

            elif name == "virustotal_domain_lookup":
                domain = arguments["domain"]
                resp = await client.get(f"{VT_BASE}/domains/{domain}", headers=headers)
                resp.raise_for_status()
                attrs = resp.json()["data"]["attributes"]
                result = {
                    "domain": domain,
                    "mock": False,
                    **_parse_stats(attrs),
                    "registrar":    attrs.get("registrar", ""),
                    "creation_date": attrs.get("creation_date", ""),
                    "tags":         attrs.get("tags", []),
                    "reputation":   attrs.get("reputation", 0),
                    "categories":   attrs.get("categories", {}),
                    "popularity_ranks": attrs.get("popularity_ranks", {}),
                }

            else:
                result = {"error": f"Unknown tool: {name}"}

        except httpx.HTTPStatusError as e:
            try:
                api_err = e.response.json().get("error", {})
                detail  = f"{api_err.get('code', '')}: {api_err.get('message', e.response.text[:200])}"
            except Exception:
                detail = e.response.text[:300]
            if e.response.status_code == 404:
                result = {"error": "not_found", "detail": f"{name}: indicator not in VirusTotal database"}
            else:
                result = {"error": f"VT API error {e.response.status_code}", "detail": detail}
        except Exception as e:
            result = {"error": f"{type(e).__name__}: {e}"}

    return [types.TextContent(type="text", text=json.dumps(result, indent=2))]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
