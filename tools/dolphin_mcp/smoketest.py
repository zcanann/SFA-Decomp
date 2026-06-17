#!/usr/bin/env python3
"""Verify Dolphin's GDB stub is live and the symbol layer resolves the PC.

Run this AFTER enabling [Core] GDBPort=2159 in Dolphin.ini and booting SFA.
It connects, halts the emulator, and prints PC/LR/r3 resolved to symbols.

    python3 tools/dolphin_mcp/smoketest.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rsp import RSPClient, RSPError
from symbols import SymbolDB


def main():
    host = os.environ.get("DOLPHIN_GDB_HOST", "127.0.0.1")
    port = int(os.environ.get("DOLPHIN_GDB_PORT", "2159"))
    rsp = RSPClient(host, port)
    syms = SymbolDB(os.environ.get("DOLPHIN_GAMEID", "GSAE01"))
    print(f"symbols: {len(syms.funcs)} functions, {len(syms.splits)} units")

    try:
        rsp.connect()
    except OSError as e:
        print(f"FAIL: could not connect to {host}:{port} -- {e}")
        print("  -> Is Dolphin running with GDBPort set, and the game booted?")
        sys.exit(1)
    print(f"connected to GDB stub at {host}:{port}")

    try:
        print("halt reason:", rsp.halt_reason())
        # Force a halt so registers are stable to read.
        rsp._send_raw(b"\x03")
        try:
            rsp.recv_packet(timeout=3)
        except (TimeoutError, OSError):
            pass
        for name in ("pc", "lr", "r3", "r4", "r5"):
            v = rsp.read_reg(name)
            print(f"  {name:>3} = {v:#010x}   {syms.resolve(v)['label']}")
        print("OK -- stub is live and registers resolve. Ready for MCP.")
    except RSPError as e:
        print(f"FAIL: stub responded oddly -- {e}")
        sys.exit(1)
    finally:
        rsp.close()


if __name__ == "__main__":
    main()
