"""
MCP Server: WHOIS
Provides domain and IP WHOIS registration lookups.
Mock mode active by default — set USE_LIVE_WHOIS=true in .env for real lookups via python-whois.
"""

import asyncio
import json
import os
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

MOCK_DOMAIN_WHOIS = {
    "suspicious": {
        "registrar": "Namecheap, Inc.",
        "creation_date": "2023-12-01",
        "expiration_date": "2024-12-01",
        "updated_date": "2023-12-01",
        "name_servers": ["ns1.privateservers.ru", "ns2.privateservers.ru"],
        "registrant_country": "RU",
        "registrant_org": "PRIVACY PROTECTED",
        "status": "clientTransferProhibited",
        "age_days": 45,
        "privacy_protected": True,
    },
    "legitimate": {
        "registrar": "GoDaddy.com, LLC",
        "creation_date": "2010-03-15",
        "expiration_date": "2030-03-15",
        "updated_date": "2023-03-10",
        "name_servers": ["ns1.godaddy.com", "ns2.godaddy.com"],
        "registrant_country": "US",
        "registrant_org": "Example Corporation",
        "status": "clientDeleteProhibited clientRenewProhibited clientTransferProhibited",
        "age_days": 5150,
        "privacy_protected": False,
    },
}

MOCK_IP_WHOIS = {
    "suspicious": {
        "network": "185.220.0.0/16",
        "country": "RU",
        "org": "Suspicious Hosting LLC",
        "asn": "AS12345",
        "asn_description": "SUSPICIOUS-HOSTING",
        "abuse_contact": "abuse@suspicious-hosting.ru",
        "created": "2018-06-01",
        "updated": "2023-01-10",
    },
    "legitimate": {
        "network": "8.8.8.0/24",
        "country": "US",
        "org": "Google LLC",
        "asn": "AS15169",
        "asn_description": "GOOGLE",
        "abuse_contact": "network-abuse@google.com",
        "created": "1992-12-01",
        "updated": "2023-09-01",
    },
}


def _looks_suspicious_domain(domain: str) -> bool:
    suspicious_tlds = [".ru", ".cn", ".tk", ".top", ".xyz", ".pw"]
    return any(domain.endswith(t) for t in suspicious_tlds)


def _looks_suspicious_ip(ip: str) -> bool:
    suspicious_prefixes = ["185.", "194.", "91.", "45.33.", "5.188."]
    return any(ip.startswith(p) for p in suspicious_prefixes)


app = Server("whois")


@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="whois_domain",
            description=(
                "Perform a WHOIS lookup on a domain to retrieve registration details: "
                "registrar, creation date, expiry, name servers, registrant country, "
                "and privacy protection status. Useful for detecting newly registered "
                "or privacy-shielded domains associated with malicious infrastructure."
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
        types.Tool(
            name="whois_ip",
            description=(
                "Perform a WHOIS lookup on an IP address to retrieve network block info: "
                "ASN, organization, country, and abuse contact. Useful for identifying "
                "hosting providers associated with malicious activity."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "IPv4 address to look up",
                    }
                },
                "required": ["ip"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    use_live = os.getenv("USE_LIVE_WHOIS", "false").lower() == "true"

    if use_live:
        try:
            import whois  # type: ignore
            if name == "whois_domain":
                w = whois.whois(arguments["domain"])
                result = {k: str(v) for k, v in w.items() if v is not None}
            elif name == "whois_ip":
                result = {"note": "Live IP WHOIS not implemented — use ipwhois library"}
            else:
                result = {"error": f"Unknown tool: {name}"}
        except Exception as e:
            result = {"error": str(e)}
    else:
        if name == "whois_domain":
            domain = arguments["domain"]
            template = "suspicious" if _looks_suspicious_domain(domain) else "legitimate"
            result = {"domain": domain, "mock": True, **MOCK_DOMAIN_WHOIS[template]}
        elif name == "whois_ip":
            ip = arguments["ip"]
            template = "suspicious" if _looks_suspicious_ip(ip) else "legitimate"
            result = {"ip": ip, "mock": True, **MOCK_IP_WHOIS[template]}
        else:
            result = {"error": f"Unknown tool: {name}"}

    return [types.TextContent(type="text", text=json.dumps(result, indent=2))]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
