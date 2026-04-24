"""
MCP Server: Threat Intelligence
Queries AbuseIPDB and OTX AlienVault for IP/domain/hash reputation.
Requires ABUSEIPDB_API_KEY and OTX_API_KEY in environment. No mock fallback when keys are present.
"""

import asyncio
import json
import os
import sys
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types
import httpx

ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"
OTX_BASE       = "https://otx.alienvault.com/api/v1"

# AbuseIPDB category codes -> human readable
ABUSE_CATEGORIES = {
    3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
    6: "Ping of Death", 7: "Phishing", 9: "Open Proxy",
    10: "Web Spam", 11: "Email Spam", 14: "Port Scan",
    15: "Hacking", 18: "Brute-Force", 19: "Bad Web Bot",
    20: "Exploited Host", 21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}

app = Server("threatintel")


@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="abuseipdb_lookup",
            description=(
                "Query AbuseIPDB for an IP address's abuse history. Returns confidence score "
                "(0-100), total report count, distinct reporting users, ISP info, and "
                "categories of abuse (SSH brute force, port scan, C2, etc.)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "IPv4 address to check"},
                    "max_age_days": {
                        "type": "integer",
                        "description": "Only include reports from the last N days (default 90)",
                        "default": 90,
                    },
                },
                "required": ["ip"],
            },
        ),
        types.Tool(
            name="otx_lookup",
            description=(
                "Query OTX AlienVault for threat intelligence on an IP, domain, or file hash. "
                "Returns associated pulse count, threat actor attributions, malware families, "
                "passive DNS, and targeted countries."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "indicator": {
                        "type": "string",
                        "description": "IP address, domain, or file hash to look up",
                    },
                    "indicator_type": {
                        "type": "string",
                        "enum": ["ip", "domain", "hash"],
                        "description": "Type of indicator",
                    },
                },
                "required": ["indicator", "indicator_type"],
            },
        ),
    ]


async def _abuseipdb_lookup(ip: str, max_age_days: int) -> dict:
    key = os.getenv("ABUSEIPDB_API_KEY", "")
    if not key:
        return {"error": "ABUSEIPDB_API_KEY is not set"}

    headers = {"Key": key, "Accept": "application/json"}
    params  = {"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": True}

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(f"{ABUSEIPDB_BASE}/check", headers=headers, params=params)
        resp.raise_for_status()
        data = resp.json().get("data", {})

    reports = data.get("reports", [])
    for r in reports:
        r["category_names"] = [ABUSE_CATEGORIES.get(c, f"Category {c}") for c in r.get("categories", [])]

    return {
        "ip":                   ip,
        "mock":                 False,
        "isWhitelisted":        data.get("isWhitelisted", False),
        "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
        "countryCode":          data.get("countryCode", ""),
        "usageType":            data.get("usageType", ""),
        "isp":                  data.get("isp", ""),
        "domain":               data.get("domain", ""),
        "hostnames":            data.get("hostnames", []),
        "totalReports":         data.get("totalReports", 0),
        "numDistinctUsers":     data.get("numDistinctUsers", 0),
        "lastReportedAt":       data.get("lastReportedAt"),
        "reports":              reports[:10],
    }


async def _otx_lookup(indicator: str, indicator_type: str) -> dict:
    key = os.getenv("OTX_API_KEY", "")
    if not key:
        return {"error": "OTX_API_KEY is not set"}

    headers = {"X-OTX-API-KEY": key, "Accept": "application/json"}

    # Map indicator_type to OTX section path
    otx_type_map = {"ip": "IPv4", "domain": "domain", "hash": "file"}
    otx_type = otx_type_map.get(indicator_type, "IPv4")

    async with httpx.AsyncClient(timeout=15) as client:
        # Fetch general + passive_dns sections
        general_resp = await client.get(
            f"{OTX_BASE}/indicators/{otx_type}/{indicator}/general",
            headers=headers,
        )
        general_resp.raise_for_status()
        general = general_resp.json()

        pulse_info = general.get("pulse_info", {})
        pulses_raw = pulse_info.get("pulses", [])
        pulses = [
            {
                "name":                p.get("name", ""),
                "description":         p.get("description", "")[:200],
                "tags":                p.get("tags", []),
                "malware_families":    p.get("malware_families", []),
                "targeted_countries":  p.get("targeted_countries", []),
            }
            for p in pulses_raw[:5]
        ]

        # Passive DNS (only for IP and domain)
        passive_dns = []
        if indicator_type in ("ip", "domain"):
            try:
                pdns_resp = await client.get(
                    f"{OTX_BASE}/indicators/{otx_type}/{indicator}/passive_dns",
                    headers=headers,
                )
                if pdns_resp.status_code == 200:
                    passive_dns = pdns_resp.json().get("passive_dns", [])[:10]
            except Exception:
                pass

    return {
        "indicator":     indicator,
        "mock":          False,
        "pulse_count":   pulse_info.get("count", 0),
        "pulses":        pulses,
        "malware_count": general.get("malware_count", 0),
        "url_count":     general.get("url_count", 0),
        "passive_dns":   passive_dns,
        "geo":           general.get("country_name", ""),
        "city":          general.get("city", ""),
    }


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    try:
        if name == "abuseipdb_lookup":
            result = await _abuseipdb_lookup(
                ip=arguments["ip"],
                max_age_days=arguments.get("max_age_days", 90),
            )

        elif name == "otx_lookup":
            result = await _otx_lookup(
                indicator=arguments["indicator"],
                indicator_type=arguments["indicator_type"],
            )

        else:
            result = {"error": f"Unknown tool: {name}"}

    except httpx.HTTPStatusError as e:
        result = {"error": f"API error {e.response.status_code}", "detail": e.response.text[:300]}
    except Exception as e:
        result = {"error": f"{type(e).__name__}: {e}"}

    return [types.TextContent(type="text", text=json.dumps(result, indent=2))]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
