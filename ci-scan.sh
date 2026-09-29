#!/bin/bash
python3 mcp_scanner.py --source ./test-target || exit 1
echo "Scan passed, continuing pipeline..."
