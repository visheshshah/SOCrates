"""
MCP Server: WHOIS
Provides domain and IP WHOIS registration lookups using live data.
Domain WHOIS: python-whois
IP WHOIS: ipwhois (RDAP/WHOIS)
No mock data — fails explicitly if a lookup errors.
"""

import asyncio
import json
import os
from datetime import datetime
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

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
                    "domain": {"type": "string", "description": "Domain name to look up"}
                },
                "required": ["domain"],
            },
        ),
        types.Tool(
            name="whois_ip",
            description=(
                "Perform a WHOIS/RDAP lookup on an IP address to retrieve network block info: "
                "ASN, organization, country, and abuse contact. Useful for identifying "
                "hosting providers associated with malicious activity."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "IPv4 address to look up"}
                },
                "required": ["ip"],
            },
        ),
    ]


def _fmt_date(val) -> str:
    """Normalize datetime / list-of-datetime / string to ISO string."""
    if val is None:
        return ""
    if isinstance(val, list):
        val = val[0]
    if isinstance(val, datetime):
        return val.isoformat()
    return str(val)


def _age_days(creation) -> int | None:
    if creation is None:
        return None
    if isinstance(creation, list):
        creation = creation[0]
    if isinstance(creation, datetime):
        return (datetime.utcnow() - creation).days
    return None


def _domain_whois(domain: str) -> dict:
    import whois  # python-whois
    w = whois.whois(domain)

    creation = w.creation_date
    age = _age_days(creation)

    registrant_org = (
        w.get("org")
        or w.get("registrant_organization")
        or w.get("registrant")
        or ""
    )
    privacy_keywords = {"privacy", "protect", "proxy", "redacted", "whoisguard", "withheld"}
    privacy_protected = any(k in str(registrant_org).lower() for k in privacy_keywords)

    ns = w.name_servers or []
    if isinstance(ns, str):
        ns = [ns]

    status = w.status or []
    if isinstance(status, str):
        status = [status]

    return {
        "domain":             domain,
        "mock":               False,
        "registrar":          str(w.registrar or ""),
        "creation_date":      _fmt_date(creation),
        "expiration_date":    _fmt_date(w.expiration_date),
        "updated_date":       _fmt_date(w.updated_date),
        "name_servers":       [str(n).lower() for n in ns],
        "registrant_country": str(w.country or w.get("registrant_country") or ""),
        "registrant_org":     str(registrant_org),
        "status":             " ".join(str(s) for s in status),
        "age_days":           age,
        "privacy_protected":  privacy_protected,
    }


def _ip_whois(ip: str) -> dict:
    from ipwhois import IPWhois
    obj    = IPWhois(ip)
    result = obj.lookup_rdap(depth=1)

    network = result.get("network", {})
    asn_desc = result.get("asn_description") or network.get("name", "")

    # Try to pull abuse contact from objects
    abuse_contact = ""
    for obj_key, obj_val in result.get("objects", {}).items():
        contact = obj_val.get("contact") or {}
        for email_entry in contact.get("email", []):
            addr = email_entry.get("value", "")
            if "abuse" in addr.lower():
                abuse_contact = addr
                break
        if abuse_contact:
            break

    return {
        "ip":              ip,
        "mock":            False,
        "network":         network.get("cidr", ""),
        "country":         result.get("asn_country_code", ""),
        "org":             asn_desc,
        "asn":             f"AS{result.get('asn', '')}",
        "asn_description": asn_desc,
        "abuse_contact":   abuse_contact,
        "created":         network.get("start_address", ""),
        "rdap_handle":     network.get("handle", ""),
    }


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    try:
        if name == "whois_domain":
            result = await asyncio.get_event_loop().run_in_executor(
                None, _domain_whois, arguments["domain"]
            )
        elif name == "whois_ip":
            result = await asyncio.get_event_loop().run_in_executor(
                None, _ip_whois, arguments["ip"]
            )
        else:
            result = {"error": f"Unknown tool: {name}"}

    except Exception as e:
        result = {"error": f"{type(e).__name__}: {e}"}

    return [types.TextContent(type="text", text=json.dumps(result, indent=2))]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
