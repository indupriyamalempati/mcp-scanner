#!/usr/bin/env python3
"""
MCP Security Scanner v2.2

Two modes:
  --server <cmd> [args...]   Metadata scan of a running MCP server (MCP-001..006)
  --source <path>            Taint analysis of Python source code (MCP-007)

Usage:
  python3 mcp_scanner.py --server python3 test_server.py
  python3 mcp_scanner.py --source ./test-target
"""
import argparse
import ast
import asyncio
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# ============================================================
# Metadata mode constants
# ============================================================
DANGER = ["exec", "shell", "run", "system", "eval", "command"]
INJECT = [r"ignore\s+previous", r"<\s*important", r"do\s+not\s+tell", r"instead\s+run"]
SSRF = ["url", "endpoint", "target", "uri", "host"]
TRAV = ["path", "file", "filename", "dir"]
SAFE_WORDS = ["allowed", "restricted", "permitted", "sanitized", "validated",
              "within", "confined", "enforced", "must be inside", "deprecated"]

# ============================================================
# Taint mode constants
# ============================================================
DANGEROUS_SINKS = {
    "os.system": "SHELL", "os.popen": "SHELL", "os.spawn": "SHELL",
    "subprocess.run": "SHELL", "subprocess.Popen": "SHELL",
    "subprocess.call": "SHELL", "subprocess.check_output": "SHELL",
    "eval": "CODE", "exec": "CODE", "compile": "CODE", "__import__": "CODE",
    "cursor.execute": "SQL", "connection.execute": "SQL",
    "session.execute": "SQL", "engine.execute": "SQL",
    "open": "FILE",
    "requests.get": "NETWORK", "requests.post": "NETWORK",
    "urllib.request.urlopen": "NETWORK", "urlopen": "NETWORK",
}

SANITIZER_SIGNALS = [
    "realpath", "startswith", "urlparse", "sanitize", "validate", "escape",
    "quote", "allowlist", "whitelist", "safe_join", "secure_filename",
]

PASS_THROUGH_MARKERS = ["client", "fetcher", "api", "session", "db",
                        "http", "connection", "requests"]

# ============================================================
# Validation agent — filters false positives
# ============================================================
READ_ONLY_PREFIXES = ("get_", "list_", "search_", "read_", "find_", "fetch_")
WRITE_PREFIXES = ("create_", "update_", "delete_", "add_", "move_", "copy_",
                  "set_", "put_", "remove_", "upload_", "download_", "post_")

NETWORK_SINK_KEYWORDS = ["session.get", "session.post", "requests.", "http.",
                          "urlopen", "fetch_url", "download"]


def validate_finding(tool_name, sink_name, category):
    """Return (final_severity, reason) for a taint finding."""
    tool_lower = tool_name.lower()
    sink_lower = sink_name.lower()

    # Rule 1: Network sinks on transfer tools are HIGH
    if any(ns in sink_lower for ns in NETWORK_SINK_KEYWORDS):
        if any(tool_lower.startswith(p) for p in ("download_", "upload_", "post_", "fetch_")):
            return ("HIGH", "Network sink on data-transfer tool")

    # Rule 2: Write operations reaching any sink are HIGH
    if any(tool_lower.startswith(p) for p in WRITE_PREFIXES):
        return ("HIGH", f"Write operation ({tool_name}) reaches sink")

    # Rule 3: Read-only tools — downgrade to LOW
    if any(tool_lower.startswith(p) for p in READ_ONLY_PREFIXES):
        return ("LOW", "Read-only tool, likely internal data fetch")

    # Rule 4: Search tools — MEDIUM
    if "search" in tool_lower:
        return ("MEDIUM", "Search tool with user-controlled query")

    return ("MEDIUM", "Unclassified taint flow — needs manual review")


# ============================================================
# Metadata mode
# ============================================================
def scan_metadata_tool(name, desc, schema, findings):
    hit = [d for d in DANGER if d in name.lower()]
    if hit:
        findings.append(("HIGH", "MCP-001", name, f"Dangerous name: {hit}"))

    for p in INJECT:
        if re.search(p, desc, re.I):
            findings.append(("HIGH", "MCP-002", name, "Prompt injection in description"))
            break

    if not desc.strip():
        findings.append(("LOW", "MCP-003", name, "No description"))

    if not schema or not isinstance(schema, dict):
        return
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        return

    has_global_safety = any(w in desc.lower() for w in SAFE_WORDS)

    for pname, pdef in properties.items():
        pl = pname.lower()
        param_desc = (pdef.get("description", "") or "").lower() if isinstance(pdef, dict) else ""
        has_param_safety = any(w in param_desc for w in SAFE_WORDS)
        is_safe = has_global_safety or has_param_safety

        if any(s in pl for s in SSRF) and not is_safe:
            findings.append(("HIGH", "MCP-004", name, f"SSRF risk: parameter '{pname}'"))
        if any(t in pl for t in TRAV) and not is_safe:
            findings.append(("MEDIUM", "MCP-005", name, f"Path traversal risk: parameter '{pname}'"))
        if isinstance(pdef, dict) and "type" not in pdef:
            findings.append(("LOW", "MCP-006", name, f"Untyped parameter '{pname}'"))


async def run_server_scan(server_cmd):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    print(f"[*] Mode: metadata scan")
    print(f"[*] Target: {' '.join(server_cmd)}\n")

    params = StdioServerParameters(command=server_cmd[0], args=server_cmd[1:])
    findings = []
    tool_count = 0

    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            tools = (await s.list_tools()).tools
            tool_count = len(tools)
            print(f"[+] Found {tool_count} tool(s)\n")

            for t in tools:
                desc = t.description or ""
                schema = getattr(t, "input_schema", None)
                scan_metadata_tool(t.name, desc, schema, findings)

    return findings, tool_count


# ============================================================
# Taint mode
# ============================================================
class TaintVisitor(ast.NodeVisitor):
    """Walk a function body, propagate taint from params to sinks."""

    def __init__(self, sources):
        self.tainted = set(sources)
        self.sink_hits = []
        self.has_sanitizer = False

    def visit_Assign(self, node):
        rhs_names = {n.id for n in ast.walk(node.value) if isinstance(n, ast.Name)}
        if rhs_names & self.tainted:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted.add(target.id)
        self.generic_visit(node)

    def visit_Call(self, node):
        func_name = self._call_name(node)
        if func_name:
            if any(sig in func_name.lower() for sig in SANITIZER_SIGNALS):
                self.has_sanitizer = True

            arg_names = {n.id for a in node.args for n in ast.walk(a)
                         if isinstance(n, ast.Name)}
            tainted_arg = bool(arg_names & self.tainted)

            if tainted_arg:
                for sink, category in DANGEROUS_SINKS.items():
                    if func_name.endswith(sink) or func_name == sink:
                        self.sink_hits.append((sink, category, node.lineno))
                        break
                else:
                    parts = func_name.split(".")
                    if len(parts) >= 2:
                        base_obj = parts[0].lower()
                        if any(m in base_obj for m in PASS_THROUGH_MARKERS):
                            self.sink_hits.append((func_name, "PASS_THROUGH", node.lineno))

        self.generic_visit(node)

    @staticmethod
    def _call_name(node):
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts = []
            cur = node.func
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            return ".".join(reversed(parts))
        return None


def is_tool_function(node):
    """Detect tool functions by decorator."""
    tool_attrs = {"tool", "function_tool", "kernel_function", "call_tool",
                  "list_tools", "function"}
    for dec in node.decorator_list:
        if isinstance(dec, ast.Name) and dec.id in tool_attrs:
            return True
        if isinstance(dec, ast.Attribute) and dec.attr in tool_attrs:
            return True
        if isinstance(dec, ast.Call):
            if isinstance(dec.func, ast.Name) and dec.func.id in tool_attrs:
                return True
            if isinstance(dec.func, ast.Attribute) and dec.func.attr in tool_attrs:
                return True
    return False


def analyze_python_file(path):
    findings = []
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not is_tool_function(node):
            continue

        sources = [a.arg for a in node.args.args if a.arg not in ("self", "cls")]
        if not sources:
            continue

        visitor = TaintVisitor(sources)
        for child in node.body:
            visitor.visit(child)

        seen_sinks = set()
        for sink, category, line in visitor.sink_hits:
            if visitor.has_sanitizer:
                continue
            if sink in seen_sinks:
                continue
            seen_sinks.add(sink)

            severity, reason = validate_finding(node.name, sink, category)
            findings.append({
                "severity": severity,
                "rule": "MCP-007",
                "tool": node.name,
                "issue": f"Taint flow: {sources} → {sink} ({category}) — {reason}",
                "location": {"file": str(path), "line": line},
            })
    return findings


def run_source_scan(source_path):
    root = Path(source_path).resolve()
    if not root.exists():
        print(f"[!] Path not found: {root}")
        sys.exit(2)

    print(f"[*] Mode: taint analysis")
    print(f"[*] Target: {root}\n")

    py_files = [f for f in root.rglob("*.py")
                if "venv" not in f.parts and ".venv" not in f.parts
                and "site-packages" not in f.parts and "node_modules" not in f.parts]

    print(f"[+] Scanning {len(py_files)} Python file(s)\n")

    all_findings = []
    for f in py_files:
        all_findings.extend(analyze_python_file(f))

    return all_findings, len(py_files)


# ============================================================
# Reporting
# ============================================================
def print_and_save(findings, scanned_count, mode):
    print("=" * 70)
    if not findings:
        print("[OK] No issues found.")
    else:
        for f in findings:
            if mode == "metadata":
                sev, rule, tool, issue = f
                print(f"[{sev}] [{rule}] {tool}: {issue}")
            else:
                print(f"[{f['severity']}] [{f['rule']}] {f['tool']}: {f['issue']}")
                if "location" in f:
                    print(f"    at {f['location']['file']}:{f['location']['line']}")
    print("=" * 70)

    report = {
        "mode": mode,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "scanned_count": scanned_count,
        "findings_count": len(findings),
        "findings": [],
    }
    if mode == "metadata":
        for sev, rule, tool, issue in findings:
            report["findings"].append({"severity": sev, "rule": rule, "tool": tool, "issue": issue})
    else:
        report["findings"] = findings

    with open("scan_report.json", "w") as fh:
        json.dump(report, fh, indent=2)

    def get_sev(f):
        return f[0] if mode == "metadata" else f["severity"]

    high = sum(1 for f in findings if get_sev(f) == "HIGH")
    medium = sum(1 for f in findings if get_sev(f) == "MEDIUM")
    low = sum(1 for f in findings if get_sev(f) == "LOW")
    print(f"\n[+] Report saved. Summary: {high} HIGH, {medium} MEDIUM, {low} LOW")

    return 1 if high > 0 else 0


# ============================================================
# CLI
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="MCP Security Scanner v2.2")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--server", nargs="+", help="MCP server command (metadata scan)")
    group.add_argument("--source", help="Path to Python source directory (taint scan)")
    args = parser.parse_args()

    if args.server:
        findings, count = asyncio.run(run_server_scan(args.server))
        exit_code = print_and_save(findings, count, "metadata")
    else:
        findings, count = run_source_scan(args.source)
        exit_code = print_and_save(findings, count, "taint")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
