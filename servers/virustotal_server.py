"""
MCP Server: VirusTotal
Provides IP, domain, and file hash reputation lookups.
Currently returns mock data — swap VIRUSTOTAL_API_KEY in .env to go live.
"""

import asyncio
import json
import os
import sys
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

# Mock responses simulate realistic VT API output
MOCK_IP_RESPONSES = {
    "default_malicious": {
        "malicious": 12,
        "suspicious": 3,
        "harmless": 15,
        "undetected": 45,
        "country": "RU",
        "asn": "AS12345",
        "as_owner": "Suspicious Hosting LLC",
        "last_analysis_date": "2024-01-15",
        "tags": ["malware", "c2"],
        "reputation": -25,
    },
    "default_clean": {
        "malicious": 0,
        "suspicious": 1,
        "harmless": 70,
        "undetected": 5,
        "country": "US",
        "asn": "AS15169",
        "as_owner": "Google LLC",
        "last_analysis_date": "2024-01-15",
        "tags": [],
        "reputation": 5,
    },
}

MOCK_HASH_RESPONSES = {
    "malicious_hash": {
        "malicious": 58,
        "suspicious": 4,
        "harmless": 2,
        "undetected": 10,
        "type_description": "Win32 EXE",
        "size": 204800,
        "names": ["svchost32.exe", "winupdate.exe"],
        "last_analysis_date": "2024-01-20",
        "tags": ["trojan", "rat", "persistence"],
        "reputation": -80,
        "magic": "PE32 executable (GUI) Intel 80386",
    },
    "clean_hash": {
        "malicious": 0,
        "suspicious": 0,
        "harmless": 72,
        "undetected": 2,
        "type_description": "Win32 EXE",
        "size": 1024000,
        "names": ["chrome.exe"],
        "last_analysis_date": "2024-01-18",
        "tags": [],
        "reputation": 20,
        "magic": "PE32 executable (GUI) Intel 80386",
    },
}


def _is_suspicious_ip(ip: str) -> bool:
    """Heuristic for mock: treat RFC-1918 and known-good ranges as clean."""
    suspicious_prefixes = ["185.", "194.", "91.", "45.33.", "5.188."]
    return any(ip.startswith(p) for p in suspicious_prefixes)


def _is_suspicious_hash(hash_value: str) -> bool:
    """Heuristic for mock: hashes ending in odd digits get flagged."""
    return hash_value[-1] in "13579abcef"


app = Server("virustotal")


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
                    "ip": {
                        "type": "string",
                        "description": "IPv4 or IPv6 address to look up",
                    }
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
                    "hash": {
                        "type": "string",
                        "description": "File hash to look up (MD5/SHA1/SHA256)",
                    }
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
                    "domain": {
                        "type": "string",
                        "description": "Domain name to look up",
                    }
                },
                "required": ["domain"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if api_key:
        # Live path — swap in real API calls here
        result = {"note": "Live VirusTotal API not yet implemented — add httpx calls here"}
    else:
        # Mock path
        if name == "virustotal_ip_lookup":
            ip = arguments["ip"]
            template = "default_malicious" if _is_suspicious_ip(ip) else "default_clean"
            result = {"ip": ip, "mock": True, **MOCK_IP_RESPONSES[template]}

        elif name == "virustotal_hash_lookup":
            hash_value = arguments["hash"]
            template = "malicious_hash" if _is_suspicious_hash(hash_value) else "clean_hash"
            result = {"hash": hash_value, "mock": True, **MOCK_HASH_RESPONSES[template]}

        elif name == "virustotal_domain_lookup":
            domain = arguments["domain"]
            suspicious_tlds = [".ru", ".cn", ".tk", ".top", ".xyz"]
            is_suspicious = any(domain.endswith(t) for t in suspicious_tlds)
            result = {
                "domain": domain,
                "mock": True,
                "malicious": 18 if is_suspicious else 0,
                "suspicious": 5 if is_suspicious else 1,
                "harmless": 10 if is_suspicious else 68,
                "registrar": "NameCheap" if is_suspicious else "GoDaddy",
                "creation_date": "2023-11-01" if is_suspicious else "2010-03-15",
                "tags": ["phishing", "malware-distribution"] if is_suspicious else [],
                "reputation": -40 if is_suspicious else 10,
            }
        else:
            result = {"error": f"Unknown tool: {name}"}

    return [types.TextContent(type="text", text=json.dumps(result, indent=2))]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
