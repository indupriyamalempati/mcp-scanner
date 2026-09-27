import asyncio
import json
import re
import sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# ============ CONFIGURATION ============
# Change this line to point at any MCP server you want to scan.
# Test server: ["python3", "/home/sansforensics/mcp-scanner/test_server.py"]
# Real server: ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
SERVER = ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]

# ============ DETECTION RULES ============

# MCP-001: Dangerous tool names
DANGER = ["exec", "shell", "run", "system", "eval", "command"]

# MCP-002: Prompt injection patterns in tool descriptions
INJECT = [
    r"ignore\s+previous",
    r"<\s*important",
    r"do\s+not\s+tell",
    r"instead\s+run",
]

# MCP-004: Parameters that look like URLs (SSRF risk)
SSRF = ["url", "endpoint", "target", "uri", "host"]

# MCP-005: Parameters that look like file paths (traversal risk)
TRAV = ["path", "file", "filename", "dir"]

# Words in descriptions that signal the server enforces access restrictions
SAFE_WORDS = [
    "allowed", "restricted", "permitted", "sanitized", "validated",
    "within", "confined", "enforced", "must be inside", "deprecated",
]


# ============ TOOL ANALYSIS ============

def scan_tool(name, desc, schema, findings):
    """Run all checks against one tool."""

    # MCP-001: Dangerous name
    hit = [d for d in DANGER if d in name.lower()]
    if hit:
        findings.append(("HIGH", "MCP-001", name, f"Dangerous name: {hit}"))

    # MCP-002: Prompt injection in description
    for p in INJECT:
        if re.search(p, desc, re.I):
            findings.append(("HIGH", "MCP-002", name, "Prompt injection in description"))
            break

    # MCP-003: Missing description
    if not desc.strip():
        findings.append(("LOW", "MCP-003", name, "No description"))

    # Schema checks (MCP-004, MCP-005, MCP-006)
    if not schema or not isinstance(schema, dict):
        return
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        return

    # Check for global safety signals in the tool description
    full_desc_lower = desc.lower()
    has_global_safety = any(w in full_desc_lower for w in SAFE_WORDS)

    for pname, pdef in properties.items():
        pl = pname.lower()

        # Check parameter-level description for safety signals
        param_desc = ""
        if isinstance(pdef, dict):
            param_desc = (pdef.get("description", "") or "").lower()
        has_param_safety = any(w in param_desc for w in SAFE_WORDS)

        is_safe = has_global_safety or has_param_safety

        # MCP-004: SSRF
        if any(s in pl for s in SSRF) and not is_safe:
            findings.append(("HIGH", "MCP-004", name, f"SSRF risk: parameter '{pname}'"))

        # MCP-005: Path traversal
        if any(t in pl for t in TRAV) and not is_safe:
            findings.append(("MEDIUM", "MCP-005", name, f"Path traversal risk: parameter '{pname}'"))

        # MCP-006: Untyped parameter
        if isinstance(pdef, dict) and "type" not in pdef:
            findings.append(("LOW", "MCP-006", name, f"Untyped parameter '{pname}'"))


# ============ MAIN SCAN ============

async def main():
    print("[*] MCP scanner starting...")
    print(f"[*] Target: {' '.join(SERVER)}\n")

    params = StdioServerParameters(command=SERVER[0], args=SERVER[1:])

    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            tools = (await s.list_tools()).tools
            print(f"[+] Found {len(tools)} tool(s)\n")
            print("=" * 70)

            findings = []
            for t in tools:
                desc = t.description or ""
                schema = getattr(t, "input_schema", None)
                scan_tool(t.name, desc, schema, findings)

            if not findings:
                print("[OK] No issues found.")
            else:
                for sev, rule, tool, issue in findings:
                    print(f"[{sev}] [{rule}] {tool}: {issue}")

            print("=" * 70)

            report = {
                "target": SERVER,
                "tools_scanned": len(tools),
                "findings_count": len(findings),
                "findings": [
                    {"severity": s, "rule": r, "tool": t, "issue": i}
                    for s, r, t, i in findings
                ],
            }
            with open("scan_report.json", "w") as f:
                json.dump(report, f, indent=2)

            high = sum(1 for f in findings if f[0] == "HIGH")
            medium = sum(1 for f in findings if f[0] == "MEDIUM")
            low = sum(1 for f in findings if f[0] == "LOW")
            print(f"\n[+] Report saved. Summary: {high} HIGH, {medium} MEDIUM, {low} LOW")

            return 1 if high > 0 else 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
