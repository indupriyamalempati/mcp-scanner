# MCP Security Scanner

A Python scanner that inspects Model Context Protocol (MCP) servers for security weaknesses. Supports two modes: metadata scanning of live servers, and taint analysis of Python source code.

## What It Detects

### Metadata mode (`--server`)

| Rule    | Severity | Description |
|---------|----------|-------------|
| MCP-001 | HIGH     | Dangerous tool names (exec, shell, run, etc.) |
| MCP-002 | HIGH     | Prompt injection patterns in tool descriptions |
| MCP-003 | LOW      | Tools with no description |
| MCP-004 | HIGH     | SSRF-prone URL parameters with no declared validation |
| MCP-005 | MEDIUM   | Path-traversal-prone file parameters with no restriction |
| MCP-006 | LOW      | Parameters with no declared type constraint |

### Taint mode (`--source`)

| Rule    | Severity | Description |
|---------|----------|-------------|
| MCP-007 | Variable | Taint flows from tool parameters to dangerous sinks |

The taint analyzer identifies tool entry points (decorator-based), traces parameter data flow through the function, detects when tainted values reach dangerous sinks (shell execution, code execution, SQL, file operations, network calls), and applies a validation agent to classify findings by risk context.

## How It Works

**Metadata mode:** Connects to an MCP server over stdio, calls `tools/list`, analyzes each tool's name, description, and input schema.

**Taint mode:** Parses Python source code with AST analysis. Finds functions decorated with `@tool`, `@mcp.tool`, `@confluence_mcp.tool(...)`, etc. Marks every parameter as a taint source. Tracks propagation through assignments and function calls. Reports when tainted data reaches:
- Direct sinks: `os.system`, `subprocess.run`, `eval`, `exec`, `open`, `requests.get`, `cursor.execute`
- Pass-through sinks: method calls on objects named `client`, `fetcher`, `api`, `session`, `db`, `http`

The validation agent then classifies each finding:
- **HIGH** — network sink on transfer tool, or write operation reaching any sink
- **MEDIUM** — search tool with user-controlled query
- **LOW** — read-only tool accessing internal data

## Installation

```bash
git clone https://github.com/indupriyamalempati/mcp-scanner.git
cd mcp-scanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
