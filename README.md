# MCP Security Scanner

A lightweight Python scanner that inspects Model Context Protocol (MCP) servers
for common security weaknesses in tool definitions.

## What It Detects

| Rule    | Severity | Description |
|---------|----------|-------------|
| MCP-001 | HIGH     | Dangerous tool names (exec, shell, run, etc.) |
| MCP-002 | HIGH     | Prompt injection patterns in tool descriptions |
| MCP-003 | LOW      | Tools with no description |
| MCP-004 | HIGH     | SSRF-prone URL parameters with no declared validation |
| MCP-005 | MEDIUM   | Path-traversal-prone file parameters with no restriction |
| MCP-006 | LOW      | Parameters with no declared type constraint |

## How It Works

The scanner connects to an MCP server over stdio, calls `tools/list`, and
analyzes each tool's name, description, and input schema. It outputs results
to the console and saves a JSON report. The exit code is `1` if any HIGH
findings exist, `0` otherwise — making it CI/CD-friendly.

## Installation

```bash
git clone https://github.com/YOUR-USERNAME/mcp-scanner.git
cd mcp-scanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
