"""Minimal GDB Remote Serial Protocol (RSP) client for Dolphin's GDB stub.

Dolphin exposes a GDB stub when [Core] GDBPort is set in Dolphin.ini. It speaks
the GDB Remote Serial Protocol over a TCP socket. This client implements just
the packets we need for breakpoint/watchpoint spelunking, with zero external
dependencies.

Register numbering (from Dolphin Source/Core/Core/PowerPC/GDBStub.cpp):
    0-31    GPR0-GPR31      4 bytes
    32-63   PS0-PS31 (FPR)  8 bytes
    64      PC              4 bytes
    65      MSR             4 bytes
    66      CR              4 bytes
    67      LR              4 bytes
    68      CTR             4 bytes
    69      XER             4 bytes
    70      FPSCR           4 bytes

Breakpoint types (Z/z packets):
    0 = ExecuteSoft   2 = Write watch   3 = Read watch   4 = Access watch
"""
from __future__ import annotations

import re
import socket
import struct

# Stop-reply signature: T<hex><hex> or S<hex><hex>. A register/memory data reply
# is hex digits or "E.."/"OK" and never starts like this, so when we expect data
# we can safely skip a stray async stop reply left in the stream.
STOP_RE = re.compile(r"^[TS][0-9a-fA-F]{2}")
# RSP error reply is exactly "E" + two hex digits. A register/memory data reply
# is the value's hex (e.g. 8 chars for a 4-byte reg), so a value whose top nibble
# is 0xE (like 0xE0001740) must NOT be mistaken for an error.
ERR_RE = re.compile(r"^E[0-9a-fA-F]{2}$")

# Symbolic register name -> (gdb register number, byte width)
REGS = {
    **{f"r{i}": (i, 4) for i in range(32)},
    **{f"f{i}": (32 + i, 8) for i in range(32)},
    "pc": (64, 4),
    "msr": (65, 4),
    "cr": (66, 4),
    "lr": (67, 4),
    "ctr": (68, 4),
    "xer": (69, 4),
    "fpscr": (70, 4),
}

BP_EXEC = 0
BP_WRITE = 2
BP_READ = 3
BP_ACCESS = 4

WATCH_MODES = {"write": BP_WRITE, "read": BP_READ, "access": BP_ACCESS}


class RSPError(Exception):
    pass


class RSPClient:
    def __init__(self, host: str = "127.0.0.1", port: int = 2159, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self._buf = b""
        self.running = False

    # ---- connection -------------------------------------------------------
    def connect(self) -> None:
        self.close()
        s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        s.settimeout(self.timeout)
        self.sock = s
        self._buf = b""
        self.running = False
        self._drain()

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None
        self._buf = b""

    @property
    def connected(self) -> bool:
        return self.sock is not None

    def _require(self) -> socket.socket:
        if self.sock is None:
            raise RSPError("not connected (call connect first)")
        return self.sock

    # ---- low-level packet I/O --------------------------------------------
    @staticmethod
    def _checksum(data: bytes) -> int:
        return sum(data) & 0xFF

    def _read_byte(self) -> int:
        s = self._require()
        if not self._buf:
            chunk = s.recv(4096)
            if not chunk:
                raise RSPError("connection closed by Dolphin")
            self._buf = chunk
        b, self._buf = self._buf[0], self._buf[1:]
        return b

    def _send_raw(self, data: bytes) -> None:
        self._require().sendall(data)

    def send_packet(self, payload: str) -> None:
        data = payload.encode("ascii", "strict")
        pkt = b"$" + data + b"#" + f"{self._checksum(data):02x}".encode("ascii")
        for _ in range(5):
            self._send_raw(pkt)
            ack = self._read_byte()
            if ack == ord("+"):
                return
            if ack == ord("-"):
                continue  # retransmit
            # Some stubs skip acks; treat anything else as the start of a reply.
            self._buf = bytes([ack]) + self._buf
            return
        raise RSPError("packet not acknowledged after retries")

    def recv_packet(self, timeout: float | None = None) -> str:
        s = self._require()
        old = s.gettimeout()
        if timeout is not None:
            s.settimeout(timeout)
        try:
            # Skip to packet start.
            while True:
                b = self._read_byte()
                if b == ord("$"):
                    break
            body = bytearray()
            while True:
                b = self._read_byte()
                if b == ord("#"):
                    break
                body.append(b)
            csum = bytes([self._read_byte(), self._read_byte()])
            got = self._checksum(bytes(body))
            want = int(csum.decode("ascii"), 16)
            if got != want:
                self._send_raw(b"-")
                raise RSPError(f"bad checksum: got {got:02x} want {want:02x}")
            self._send_raw(b"+")
            return body.decode("ascii", "replace")
        finally:
            s.settimeout(old)

    def _drain(self, timeout: float = 0.15) -> int:
        """Discard any unsolicited/leftover packets so the stream stays aligned.

        Called after a halt/stop so a stray stop reply (e.g. from an async
        Ctrl-C break) can't shift every subsequent read one packet behind.
        """
        n = 0
        while True:
            try:
                self.recv_packet(timeout=timeout)
                n += 1
            except (socket.timeout, TimeoutError, RSPError):
                break
        return n

    def command(self, payload: str, timeout: float | None = None,
                expect_data: bool = False) -> str:
        self.send_packet(payload)
        resp = self.recv_packet(timeout=timeout)
        # Skip stray async stop replies when a data/OK reply is expected.
        tries = 0
        while expect_data and STOP_RE.match(resp) and tries < 6:
            resp = self.recv_packet(timeout=timeout)
            tries += 1
        return resp

    # ---- registers --------------------------------------------------------
    def read_reg(self, name: str) -> int:
        if name not in REGS:
            raise RSPError(f"unknown register: {name}")
        num, width = REGS[name]
        resp = self.command(f"p{num:x}", expect_data=True)
        if not resp or ERR_RE.fullmatch(resp):
            raise RSPError(f"read_reg {name} failed: {resp!r}")
        return int(resp[: width * 2], 16)

    def read_gprs(self) -> dict[str, int]:
        out = {}
        for i in range(32):
            out[f"r{i}"] = self.read_reg(f"r{i}")
        for name in ("pc", "lr", "ctr", "cr", "xer", "msr"):
            out[name] = self.read_reg(name)
        return out

    def write_reg(self, name: str, value: int) -> None:
        if name not in REGS:
            raise RSPError(f"unknown register: {name}")
        num, width = REGS[name]
        hexval = f"{value & ((1 << (width * 8)) - 1):0{width * 2}x}"
        resp = self.command(f"P{num:x}={hexval}")
        if resp != "OK":
            raise RSPError(f"write_reg {name} failed: {resp!r}")

    # ---- memory -----------------------------------------------------------
    def read_memory(self, addr: int, length: int) -> bytes:
        resp = self.command(f"m{addr:x},{length:x}", expect_data=True)
        # Error is exactly "Exx"; a 1-byte read is 2 hex chars, longer reads more,
        # so an exact 3-char "Exx" is unambiguously an error (not data).
        if not resp or ERR_RE.fullmatch(resp):
            raise RSPError(f"read_memory @{addr:#x} failed: {resp!r}")
        return bytes.fromhex(resp)

    def write_memory(self, addr: int, data: bytes) -> None:
        resp = self.command(f"M{addr:x},{len(data):x}:{data.hex()}")
        if resp != "OK":
            raise RSPError(f"write_memory @{addr:#x} failed: {resp!r}")

    def read_u32(self, addr: int) -> int:
        return struct.unpack(">I", self.read_memory(addr, 4))[0]

    # ---- breakpoints / watchpoints ---------------------------------------
    def add_breakpoint(self, addr: int, bptype: int = BP_EXEC, kind: int = 4) -> None:
        resp = self.command(f"Z{bptype},{addr:x},{kind:x}")
        if resp != "OK":
            raise RSPError(f"add breakpoint type {bptype} @{addr:#x} failed: {resp!r}")

    def remove_breakpoint(self, addr: int, bptype: int = BP_EXEC, kind: int = 4) -> None:
        resp = self.command(f"z{bptype},{addr:x},{kind:x}")
        if resp != "OK":
            raise RSPError(f"remove breakpoint type {bptype} @{addr:#x} failed: {resp!r}")

    # ---- execution control -----------------------------------------------
    def halt_reason(self) -> str:
        return self.command("?")

    def step(self) -> str:
        reply = self.command("s", timeout=self.timeout)
        self._drain()
        return reply

    def cont(self, timeout: float = 30.0) -> tuple[bool, str]:
        """Continue execution and wait for a stop.

        Returns (stopped, reply). If no stop within `timeout`, sends a break
        (Ctrl-C) to halt and returns the resulting stop reply. stopped is True
        if a breakpoint/watchpoint/step caused the stop, False if we forced it.
        """
        self.send_packet("c")
        self.running = True
        try:
            reply = self.recv_packet(timeout=timeout)
        except (socket.timeout, TimeoutError):
            # Force a halt with a raw break byte, then read the stop reply.
            self._send_raw(b"\x03")
            reply = self.recv_packet(timeout=self.timeout)
            self.running = False
            self._drain()
            return False, reply
        self.running = False
        self._drain()
        return True, reply

    def resume(self) -> None:
        """Free-run: send continue and return immediately (no wait, no halt).

        While running, the stub will not answer register/memory reads -- call
        wait_stop (to catch a breakpoint) or halt before reading state.
        """
        self.send_packet("c")
        self.running = True

    def wait_stop(self, timeout: float = 30.0) -> str | None:
        """Block for a stop reply (a breakpoint/watch hit) without forcing a halt.

        Returns the stop reply, or None if still running after `timeout` (the
        game keeps running -- call again or halt).
        """
        if not self.running:
            return self.halt_reason()
        try:
            reply = self.recv_packet(timeout=timeout)
        except (socket.timeout, TimeoutError):
            return None
        self.running = False
        self._drain()
        return reply

    def halt(self) -> str:
        """Interrupt a running game with a Ctrl-C break and read the stop reply."""
        self._send_raw(b"\x03")
        reply = self.recv_packet(timeout=self.timeout)
        self.running = False
        self._drain()
        return reply
