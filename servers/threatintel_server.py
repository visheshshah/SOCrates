"""
MCP Server: Threat Intelligence
Queries AbuseIPDB and OTX AlienVault for IP/domain reputation.
Mock mode active by default.
"""

import asyncio
import json
import os
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

MOCK_ABUSEIPDB = {
    "malicious": {
        "isWhitelisted": False,
        "abuseConfidenceScore": 92,
        "countryCode": "RU",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "Suspicious Hosting LLC",
        "domain": "suspicious-hosting.ru",
        "hostnames": [],
        "totalReports": 847,
        "numDistinctUsers": 312,
        "lastReportedAt": "2024-01-15T08:23:11+00:00",
        "reports": [
            {"categories": [18, 22], "comment": "SSH brute force + port scanning"},
            {"categories": [14], "comment": "Command and control traffic detected"},
        ],
    },
    "clean": {
        "isWhitelisted": True,
        "abuseConfidenceScore": 0,
        "countryCode": "US",
        "usageType": "Search Engine Spider",
        "isp": "Google LLC",
        "domain": "google.com",
        "hostnames": ["dns.google"],
        "totalReports": 0,
        "numDistinctUsers": 0,
        "lastReportedAt": None,
        "reports": [],
    },
}

MOCK_OTX = {
    "malicious": {
        "pulse_count": 23,
        "pulses": [
            {
                "name": "APT28 C2 Infrastructure",
                "description": "Known APT28 command and control servers",
                "tags": ["apt28", "fancy-bear", "c2", "russia"],
                "references": ["https://example.com/apt28-report"],
                "targeted_countries": ["US", "EU", "UA"],
                "malware_families": ["X-Agent", "Sofacy"],
            },
            {
                "name": "Cobalt Strike Beacon Infrastructure",
                "description": "Cobalt Strike team server",
                "tags": ["cobalt-strike", "beacon", "c2"],
                "references": [],
                "targeted_countries": ["US"],
                "malware_families": ["Cobalt Strike"],
            },
        ],
        "malware_count": 15,
        "url_count": 42,
        "passive_dns": [
            {"hostname": "cmd.evil-domain.ru", "first": "2023-10-01", "last": "2024-01-10"},
        ],
        "geo": {"country_name": "Russia", "city": "Moscow"},
    },
    "clean": {
        "pulse_count": 0,
        "pulses": [],
        "malware_count": 0,
        "url_count": 0,
        "passive_dns": [],
        "geo": {"country_name": "United States", "city": "Mountain View"},
    },
}

# AbuseIPDB category codes -> human readable
ABUSE_CATEGORIES = {
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    14: "Port Scan",
    15: "Hacking",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


def _is_suspicious(value: str) -> bool:
    suspicious_patterns = ["185.", "194.", "91.", "45.33.", ".ru", ".cn", ".tk", ".top"]
    return any(value.startswith(p) or value.endswith(p) for p in suspicious_patterns)


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


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY")
    otx_key = os.getenv("OTX_API_KEY")

    if name == "abuseipdb_lookup":
        if abuseipdb_key:
            result = {"note": "Live AbuseIPDB not yet implemented — add httpx call here"}
        else:
            ip = arguments["ip"]
            template = "malicious" if _is_suspicious(ip) else "clean"
            data = dict(MOCK_ABUSEIPDB[template])
            # Resolve category codes to names
            for report in data.get("reports", []):
                report["category_names"] = [
                    ABUSE_CATEGORIES.get(c, f"Category {c}") for c in report.get("categories", [])
                ]
            result = {"ip": ip, "mock": True, **data}

    elif name == "otx_lookup":
        if otx_key:
            result = {"note": "Live OTX not yet implemented — add httpx call here"}
        else:
            indicator = arguments["indicator"]
            template = "malicious" if _is_suspicious(indicator) else "clean"
            result = {"indicator": indicator, "mock": True, **MOCK_OTX[template]}

    else:
        result = {"error": f"Unknown tool: {name}"}

    return [types.TextContent(type="text", text=json.dumps(result, indent=2))]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
