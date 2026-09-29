#!/bin/bash
python3 mcp_scanner.py --server python3 test_server.py
EXIT=$?
echo ""
echo "Scanner returned exit code: $EXIT"
if [ $EXIT -eq 1 ]; then
    echo "HIGH findings detected — build would fail in CI"
else
    echo "No HIGH findings — build would pass in CI"
fi
exit 0
