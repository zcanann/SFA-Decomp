#!/usr/bin/env python3
"""One-shot end-to-end proof: drive server.py over JSON-RPC against a live stub.

Holds a single MCP/RSP session open for the whole run (so it does NOT tear the
stub down mid-way like a bare `nc` probe would). Proves RSP + MCP + symbol
resolution against a freshly-booted, halted game.

    python3 tools/dolphin_mcp/live_proof.py
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    reqs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05", "capabilities": {}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "connect", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "whereami", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
         "params": {"name": "read_registers", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
         "params": {"name": "step", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 6, "method": "tools/call",
         "params": {"name": "whereami", "arguments": {}}},
    ]
    inp = "\n".join(json.dumps(r) for r in reqs) + "\n"
    p = subprocess.run([sys.executable, os.path.join(HERE, "server.py")],
                       input=inp, capture_output=True, text=True, timeout=30)
    if p.stderr.strip():
        print("server stderr:", p.stderr.strip(), file=sys.stderr)
    labels = {2: "connect", 3: "whereami", 4: "read_registers",
              5: "step", 6: "whereami (after step)"}
    for line in p.stdout.strip().splitlines():
        m = json.loads(line)
        mid = m.get("id")
        if mid == 1 or mid not in labels:
            continue
        res = m.get("result", {})
        body = res.get("content", [{}])[0].get("text", "")
        flag = " [isError]" if res.get("isError") else ""
        print(f"\n=== {labels[mid]}{flag} ===")
        print(body)


if __name__ == "__main__":
    main()
