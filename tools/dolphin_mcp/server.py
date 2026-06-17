#!/usr/bin/env python3
"""Dolphin debugger MCP server for SFA-Decomp.

Drives Dolphin's GDB stub (enable with [Core] GDBPort=2159 in Dolphin.ini) over
the GDB Remote Serial Protocol, exposing symbol-aware debugger tools so the
function-discovery loop (breakpoint -> run -> read r3/LR/PC -> name the function)
can be agent-driven.

Speaks the MCP stdio transport directly (newline-delimited JSON-RPC 2.0), so it
has zero external dependencies. stdout carries ONLY protocol JSON; everything
else goes to stderr.

Register and run via Claude Code:
    claude mcp add dolphin -- python3 tools/dolphin_mcp/server.py
Optional env: DOLPHIN_GDB_HOST (default 127.0.0.1), DOLPHIN_GDB_PORT (2159),
DOLPHIN_GAMEID (GSAE01).
"""
from __future__ import annotations

import json
import os
import struct
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rsp import REGS, WATCH_MODES, BP_EXEC, RSPClient, RSPError  # noqa: E402
from symbols import SymbolDB  # noqa: E402

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "dolphin-sfa", "version": "0.1.0"}


def log(*a):
    print("[dolphin-mcp]", *a, file=sys.stderr, flush=True)


class Debugger:
    """Stateful glue between the RSP client and the symbol DB."""

    def __init__(self):
        self.host = os.environ.get("DOLPHIN_GDB_HOST", "127.0.0.1")
        self.port = int(os.environ.get("DOLPHIN_GDB_PORT", "2159"))
        self.gameid = os.environ.get("DOLPHIN_GAMEID", "GSAE01")
        self.rsp = RSPClient(self.host, self.port)
        self.syms = SymbolDB(self.gameid)
        # addr -> (bptype, kind) for breakpoints/watches we've set
        self.breakpoints: dict[int, tuple[int, int]] = {}

    def ensure_connected(self):
        if not self.rsp.connected:
            self.rsp.connect()

    def ensure_halted(self):
        self.ensure_connected()
        if self.rsp.running:
            raise RSPError("game is running (resumed); call wait_stop or halt "
                           "before reading registers/memory")

    # ---- tool implementations --------------------------------------------
    def connect(self) -> dict:
        self.rsp.connect()
        reason = self.rsp.halt_reason()
        return {"connected": True, "host": self.host, "port": self.port,
                "halt_reason": reason, "symbols_loaded": len(self.syms.funcs),
                "units_loaded": len(self.syms.splits)}

    def status(self) -> dict:
        return {"connected": self.rsp.connected, "host": self.host,
                "port": self.port, "gameid": self.gameid,
                "breakpoints": {f"{a:#010x}": bt for a, (bt, _) in self.breakpoints.items()},
                "symbols_loaded": len(self.syms.funcs)}

    def whereami(self) -> dict:
        self.ensure_halted()
        pc = self.rsp.read_reg("pc")
        lr = self.rsp.read_reg("lr")
        out = {"pc": self.syms.resolve(pc), "lr": self.syms.resolve(lr)}
        return out

    def read_registers(self) -> dict:
        self.ensure_halted()
        regs = self.rsp.read_gprs()
        out = {k: f"{v:#010x}" for k, v in regs.items()}
        out["pc_resolved"] = self.syms.resolve(regs["pc"])["label"]
        out["lr_resolved"] = self.syms.resolve(regs["lr"])["label"]
        out["r3_resolved"] = self.syms.resolve(regs["r3"])["label"]
        return out

    def read_register(self, name: str) -> dict:
        self.ensure_halted()
        name = name.lower()
        if name not in REGS:
            raise RSPError(f"unknown register {name!r}; valid: r0-r31, f0-f31, "
                           "pc, lr, ctr, cr, xer, msr, fpscr")
        v = self.rsp.read_reg(name)
        out = {"name": name, "value": f"{v:#x}", "resolved": self.syms.resolve(v)["label"]}
        if name.startswith("f"):
            out["double"] = struct.unpack(">d", v.to_bytes(8, "big"))[0]
        return out

    def write_register(self, name: str, value: str) -> dict:
        self.ensure_halted()
        self.rsp.write_reg(name.lower(), int(value, 0))
        return {"ok": True, "name": name, "value": value}

    def read_memory(self, addr: str, length: int = 16) -> dict:
        self.ensure_halted()
        a = self.syms.resolve_target(addr)
        data = self.rsp.read_memory(a, int(length))
        words = [f"{struct.unpack('>I', data[i:i+4])[0]:#010x}"
                 for i in range(0, len(data) - len(data) % 4, 4)]
        return {"addr": f"{a:#010x}", "len": len(data), "hex": data.hex(),
                "words_be": words}

    def write_memory(self, addr: str, hex_bytes: str) -> dict:
        self.ensure_halted()
        a = self.syms.resolve_target(addr)
        data = bytes.fromhex(hex_bytes.replace("0x", "").replace(" ", ""))
        self.rsp.write_memory(a, data)
        return {"ok": True, "addr": f"{a:#010x}", "len": len(data)}

    def set_breakpoint(self, target: str) -> dict:
        self.ensure_connected()
        a = self.syms.resolve_target(target)
        self.rsp.add_breakpoint(a, BP_EXEC, 4)
        self.breakpoints[a] = (BP_EXEC, 4)
        return {"ok": True, "addr": f"{a:#010x}", "at": self.syms.resolve(a)["label"],
                "type": "exec"}

    def watch_memory(self, addr: str, mode: str = "write", size: int = 4) -> dict:
        self.ensure_connected()
        mode = mode.lower()
        if mode not in WATCH_MODES:
            raise RSPError(f"mode must be one of {list(WATCH_MODES)}")
        a = self.syms.resolve_target(addr)
        bt = WATCH_MODES[mode]
        self.rsp.add_breakpoint(a, bt, int(size))
        self.breakpoints[a] = (bt, int(size))
        return {"ok": True, "addr": f"{a:#010x}", "mode": mode, "size": int(size)}

    def clear_breakpoint(self, target: str) -> dict:
        self.ensure_connected()
        a = self.syms.resolve_target(target)
        ent = self.breakpoints.pop(a, None)
        bt, kind = ent if ent else (BP_EXEC, 4)
        self.rsp.remove_breakpoint(a, bt, kind)
        return {"ok": True, "addr": f"{a:#010x}"}

    def clear_all_breakpoints(self) -> dict:
        self.ensure_connected()
        n = 0
        for a, (bt, kind) in list(self.breakpoints.items()):
            try:
                self.rsp.remove_breakpoint(a, bt, kind)
                n += 1
            except RSPError:
                pass
        self.breakpoints.clear()
        return {"ok": True, "cleared": n}

    def _stop_report(self, stopped: bool, reply: str) -> dict:
        pc = self.rsp.read_reg("pc")
        lr = self.rsp.read_reg("lr")
        r3 = self.rsp.read_reg("r3")
        return {
            "stopped": stopped,
            "reply": reply,
            "pc": self.syms.resolve(pc)["label"],
            "pc_addr": f"{pc:#010x}",
            "lr": self.syms.resolve(lr)["label"],
            "r3": f"{r3:#010x}",
            "r3_resolved": self.syms.resolve(r3)["label"],
        }

    def continue_(self, timeout: float = 30.0) -> dict:
        self.ensure_connected()
        stopped, reply = self.rsp.cont(timeout=float(timeout))
        out = self._stop_report(stopped, reply)
        if not stopped:
            out["note"] = (f"no breakpoint hit within {timeout}s; forced halt. "
                           "Trigger the in-game action then call continue again, "
                           "or use resume + wait_stop for free play.")
        return out

    def resume(self) -> dict:
        """Free-run the game (no blocking wait). Use for booting / free play."""
        self.ensure_connected()
        self.rsp.resume()
        return {"running": True,
                "note": "game is running freely. Call wait_stop to catch a "
                        "breakpoint/watch, or halt to break in."}

    def wait_stop(self, timeout: float = 30.0) -> dict:
        """Wait for a breakpoint/watch to fire while the game runs freely."""
        self.ensure_connected()
        reply = self.rsp.wait_stop(timeout=float(timeout))
        if reply is None:
            return {"stopped": False, "running": True,
                    "note": f"still running after {timeout}s; call wait_stop "
                            "again or halt."}
        return self._stop_report(True, reply)

    def step(self) -> dict:
        self.ensure_halted()
        reply = self.rsp.step()
        return self._stop_report(True, reply)

    def halt(self) -> dict:
        self.ensure_connected()
        reply = self.rsp.halt()
        return self._stop_report(False, reply)

    def lookup(self, target: str) -> dict:
        """Resolve a symbol name to address or an address to a symbol."""
        a = self.syms.resolve_target(target)
        return self.syms.resolve(a)


# ---- MCP tool schema definitions ----------------------------------------
def tool_defs():
    addr = {"type": "string", "description": "hex address (0x...), decimal, or symbol name"}
    return [
        ("connect", "Connect to Dolphin's GDB stub and report halt state + symbol counts.", {}),
        ("status", "Show connection state and active breakpoints (no Dolphin call).", {}),
        ("whereami", "Resolve current PC and LR to function+offset and unit.", {}),
        ("read_registers", "Read all GPRs + pc/lr/ctr/cr/xer/msr; resolves pc/lr/r3 to symbols.", {}),
        ("read_register", "Read one register (r0-r31, f0-f31, pc, lr, ctr, cr, xer, msr, fpscr).",
         {"name": {"type": "string"}}),
        ("write_register", "Write one register.", {"name": {"type": "string"}, "value": addr}),
        ("read_memory", "Read memory; returns raw hex + big-endian u32 words.",
         {"addr": addr, "length": {"type": "integer", "default": 16}}),
        ("write_memory", "Write raw bytes (hex string) to memory.",
         {"addr": addr, "hex_bytes": {"type": "string"}}),
        ("set_breakpoint", "Set an execution breakpoint at a symbol or address.", {"target": addr}),
        ("watch_memory", "Set a hardware watchpoint (mode: write|read|access).",
         {"addr": addr, "mode": {"type": "string", "default": "write"},
          "size": {"type": "integer", "default": 4}}),
        ("clear_breakpoint", "Remove a breakpoint/watchpoint at a symbol or address.", {"target": addr}),
        ("clear_all_breakpoints", "Remove all breakpoints/watchpoints we set.", {}),
        ("continue", "Resume the game; blocks until a breakpoint hits or timeout (then halts).",
         {"timeout": {"type": "number", "default": 30}}),
        ("resume", "Free-run the game without blocking (for booting / free play). "
                   "Then use wait_stop or halt.", {}),
        ("wait_stop", "Wait for a breakpoint/watch to fire after resume; does not "
                      "force a halt on timeout.", {"timeout": {"type": "number", "default": 30}}),
        ("step", "Single-step one instruction.", {}),
        ("halt", "Halt the running emulator (Ctrl-C break).", {}),
        ("lookup", "Resolve a symbol name <-> address without touching Dolphin.", {"target": addr}),
    ]


REQUIRED = {
    "read_register": ["name"], "write_register": ["name", "value"],
    "read_memory": ["addr"], "write_memory": ["addr", "hex_bytes"],
    "set_breakpoint": ["target"], "watch_memory": ["addr"],
    "clear_breakpoint": ["target"], "lookup": ["target"],
}

# tool name -> Debugger method name (continue is a keyword)
DISPATCH = {
    "connect": "connect", "status": "status", "whereami": "whereami",
    "read_registers": "read_registers", "read_register": "read_register",
    "write_register": "write_register", "read_memory": "read_memory",
    "write_memory": "write_memory", "set_breakpoint": "set_breakpoint",
    "watch_memory": "watch_memory", "clear_breakpoint": "clear_breakpoint",
    "clear_all_breakpoints": "clear_all_breakpoints", "continue": "continue_",
    "resume": "resume", "wait_stop": "wait_stop",
    "step": "step", "halt": "halt", "lookup": "lookup",
}


def build_tools_list():
    tools = []
    for name, desc, props in tool_defs():
        schema = {"type": "object", "properties": props}
        if name in REQUIRED:
            schema["required"] = REQUIRED[name]
        tools.append({"name": name, "description": desc, "inputSchema": schema})
    return tools


class Server:
    def __init__(self):
        self.dbg = Debugger()
        self.tools = build_tools_list()

    def handle(self, msg: dict):
        method = msg.get("method")
        mid = msg.get("id")
        if method == "initialize":
            client_proto = (msg.get("params") or {}).get("protocolVersion", PROTOCOL_VERSION)
            return self._ok(mid, {
                "protocolVersion": client_proto,
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            })
        if method in ("notifications/initialized", "initialized"):
            return None
        if method == "ping":
            return self._ok(mid, {})
        if method == "tools/list":
            return self._ok(mid, {"tools": self.tools})
        if method == "tools/call":
            return self._call(mid, msg.get("params") or {})
        if mid is not None:
            return self._err(mid, -32601, f"method not found: {method}")
        return None

    def _call(self, mid, params):
        name = params.get("name")
        args = params.get("arguments") or {}
        if name not in DISPATCH:
            return self._tool_error(mid, f"unknown tool: {name}")
        try:
            fn = getattr(self.dbg, DISPATCH[name])
            result = fn(**args)
            text = json.dumps(result, indent=2)
            return self._ok(mid, {"content": [{"type": "text", "text": text}]})
        except (RSPError, KeyError, ValueError, OSError) as e:
            return self._tool_error(mid, f"{type(e).__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            log("unexpected error in", name, traceback.format_exc())
            return self._tool_error(mid, f"unexpected {type(e).__name__}: {e}")

    @staticmethod
    def _ok(mid, result):
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    @staticmethod
    def _err(mid, code, message):
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}

    @staticmethod
    def _tool_error(mid, message):
        return {"jsonrpc": "2.0", "id": mid,
                "result": {"content": [{"type": "text", "text": message}], "isError": True}}

    def run(self):
        log(f"started; target {self.dbg.host}:{self.dbg.port} gameid={self.dbg.gameid}; "
            f"{len(self.dbg.syms.funcs)} symbols, {len(self.dbg.syms.splits)} units")
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                log("bad json:", line[:200])
                continue
            resp = self.handle(msg)
            if resp is not None:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()


if __name__ == "__main__":
    Server().run()
