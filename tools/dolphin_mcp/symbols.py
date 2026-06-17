"""Address <-> symbol resolution for the Dolphin MCP server.

Reuses the parsing shape of tools/symbols_to_dolphin_map.py:
  config/<gameid>/symbols.txt : `name = .section:0xADDR; ... size:0xNN ... type:function`
  config/<gameid>/splits.txt  : `unit/path.c:` then indented `.text start:0xADDR end:0xADDR`

The decomp build byte-matches retail, so symbols.txt addresses are the live RAM
addresses while the game runs -- letting us turn a halted PC into
"unit/file.c::Function +0xNN".
"""
from __future__ import annotations

import bisect
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

SYM_RE = re.compile(
    r"^(?P<name>\S+)\s*=\s*\.(?P<section>\w+):0x(?P<addr>[0-9A-Fa-f]+);(?P<rest>.*)$"
)
SIZE_RE = re.compile(r"size:0x(?P<size>[0-9A-Fa-f]+)")
SPLIT_UNIT_RE = re.compile(r"^(?P<unit>\S+\.\w+):\s*$")
SPLIT_TEXT_RE = re.compile(
    r"^\s+\.text\s+start:0x(?P<start>[0-9A-Fa-f]+)\s+end:0x(?P<end>[0-9A-Fa-f]+)"
)


class SymbolDB:
    def __init__(self, gameid: str = "GSAE01", root: Path | None = None):
        self.gameid = gameid
        self.root = root or REPO_ROOT
        # functions: sorted list of (addr, size, name)
        self.funcs: list[tuple[int, int, str]] = []
        self.by_name: dict[str, tuple[int, int]] = {}
        # text splits: sorted list of (start, end, unit)
        self.splits: list[tuple[int, int, str]] = []
        self._load()

    def _cfg(self, fname: str) -> Path:
        return self.root / "config" / self.gameid / fname

    def _load(self) -> None:
        self._load_symbols()
        self._load_splits()

    def _load_symbols(self) -> None:
        path = self._cfg("symbols.txt")
        funcs = []
        for line in path.read_text().splitlines():
            m = SYM_RE.match(line.strip())
            if not m:
                continue
            rest = m.group("rest")
            if "type:function" not in rest:
                continue
            addr = int(m.group("addr"), 16)
            sm = SIZE_RE.search(rest)
            size = int(sm.group("size"), 16) if sm else 0
            name = m.group("name")
            funcs.append((addr, size, name))
            self.by_name[name] = (addr, size)
        funcs.sort()
        self.funcs = funcs
        self._func_addrs = [f[0] for f in funcs]

    def _load_splits(self) -> None:
        path = self._cfg("splits.txt")
        if not path.exists():
            return
        splits = []
        unit = None
        for line in path.read_text().splitlines():
            um = SPLIT_UNIT_RE.match(line)
            if um:
                unit = um.group("unit")
                continue
            tm = SPLIT_TEXT_RE.match(line)
            if tm and unit:
                splits.append((int(tm.group("start"), 16), int(tm.group("end"), 16), unit))
        splits.sort()
        self.splits = splits
        self._split_starts = [s[0] for s in splits]

    # ---- lookups ----------------------------------------------------------
    def unit_for(self, addr: int) -> str | None:
        if not self.splits:
            return None
        i = bisect.bisect_right(self._split_starts, addr) - 1
        if i < 0:
            return None
        start, end, unit = self.splits[i]
        return unit if start <= addr < end else None

    def func_for(self, addr: int) -> tuple[str, int, int] | None:
        """Return (name, base_addr, offset) for the function containing addr."""
        if not self.funcs:
            return None
        i = bisect.bisect_right(self._func_addrs, addr) - 1
        if i < 0:
            return None
        base, size, name = self.funcs[i]
        if size and not (base <= addr < base + size):
            # addr is in a gap after the previous function's known extent.
            if addr != base:
                return None
        return name, base, addr - base

    def resolve(self, addr: int) -> dict:
        out: dict = {"addr": addr, "addr_hex": f"{addr:#010x}"}
        f = self.func_for(addr)
        if f:
            name, base, off = f
            out["function"] = name
            out["func_base"] = f"{base:#010x}"
            out["offset"] = off
            out["label"] = f"{name}+{off:#x}" if off else name
        else:
            out["label"] = f"{addr:#010x}"
        unit = self.unit_for(addr)
        if unit:
            out["unit"] = unit
        return out

    def addr_of(self, name: str) -> int | None:
        ent = self.by_name.get(name)
        return ent[0] if ent else None

    def resolve_target(self, spec: str) -> int:
        """Accept a hex/decimal address or a symbol name; return an address."""
        spec = spec.strip()
        if spec in self.by_name:
            return self.by_name[spec][0]
        try:
            return int(spec, 16) if spec.lower().startswith("0x") else int(spec, 0)
        except ValueError:
            pass
        a = self.addr_of(spec)
        if a is not None:
            return a
        raise KeyError(f"could not resolve {spec!r} as an address or symbol name")
