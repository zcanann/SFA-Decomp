"""Creation-order .sdata2 oracle: TU-boundary detector.

MWCC emits .sdata2 in creation order: for each function in source order, the
literals interned during that function's parse, then the int->float magic
double(s) appended by its codegen.  File-scope const objects are created when
their declaration is parsed, so they head the pool.  Two consequences:

  * within one TU the first-use function index of the pool words is monotone
    once the file-scope const head block is skipped; a later inversion means
    the claim spans more than one TU,
  * a compiler literal is interned once per TU, so the same .sdata2 word
    reached from two different units proves those units are one TU.

Usage:
    python3 tools/sdata2_oracle.py                 creation-order sweep
    python3 tools/sdata2_oracle.py --unclaimed     attribute unclaimed pool
    python3 tools/sdata2_oracle.py --unit NAME     per-word detail for a unit
    python3 tools/sdata2_oracle.py --unit NAME --compare-src
                                                   compare retail vs built source
    python3 tools/sdata2_oracle.py --compare-src-sweep
                                                   summarize retail/source pool drift

Reads only the carved retail objects under build/<version>/obj.
"""

from __future__ import annotations

import argparse
import bisect
import json
import struct
import subprocess
import tempfile
from pathlib import Path

MAGIC_HI = bytes.fromhex("43300000")


def run(objdump: Path, *args) -> str:
    return subprocess.run(
        [str(objdump), *[str(a) for a in args]], capture_output=True, text=True
    ).stdout


def section(objcopy: Path, obj: Path, name: str, tmp: Path) -> bytes:
    dst = tmp / "section.bin"
    if dst.exists():
        dst.unlink()
    subprocess.run(
        [str(objcopy), "-O", "binary", f"--only-section={name}", str(obj), str(dst)],
        capture_output=True,
    )
    return dst.read_bytes() if dst.exists() else b""


def symbols(objdump: Path, obj: Path):
    functions: list[tuple[int, str]] = []
    pool: dict[str, tuple[int, int]] = {}
    for line in run(objdump, "-t", obj).splitlines():
        if "\t" not in line:
            continue
        left, right = line.split("\t", 1)
        fields = left.split()
        if len(fields) < 2:
            continue
        try:
            address = int(fields[0], 16)
        except ValueError:
            continue
        sect = fields[-1]
        rest = right.split()
        if len(rest) < 2:
            continue
        try:
            size = int(rest[0], 16)
        except ValueError:
            continue
        name = rest[1]
        if sect == ".text" and "F" in " ".join(fields[1:-1]):
            functions.append((address, name))
        elif sect == ".sdata2" and name != ".sdata2":
            pool[name] = (address, size)
    functions.sort()
    return functions, pool


def text_relocations(objdump: Path, obj: Path):
    out = []
    in_text = False
    for line in run(objdump, "-r", obj).splitlines():
        if line.startswith("RELOCATION RECORDS FOR ["):
            in_text = line.startswith("RELOCATION RECORDS FOR [.text]")
            continue
        if not in_text:
            continue
        fields = line.split()
        if len(fields) < 3 or not fields[1].startswith("R_"):
            continue
        try:
            offset = int(fields[0], 16)
        except ValueError:
            continue
        symbol, addend = fields[2], 0
        if "+" in symbol:
            symbol, tail = symbol.split("+", 1)
            try:
                addend = int(tail, 16)
            except ValueError:
                addend = 0
        out.append((offset, symbol, addend))
    return out


def first_use(functions, relocations, pool):
    addresses = [a for a, _ in functions]
    first: dict[int, int] = {}
    for offset, symbol, addend in relocations:
        if symbol not in pool:
            continue
        target = pool[symbol][0] + addend
        index = max(bisect.bisect_right(addresses, offset) - 1, 0)
        if target not in first or index < first[target]:
            first[target] = index
    return first


def unit_rows(objdump, objcopy, obj, tmp):
    functions, pool = symbols(objdump, obj)
    if not functions or not pool:
        return None
    data = section(objcopy, obj, ".sdata2", tmp)
    first = first_use(functions, text_relocations(objdump, obj), pool)
    rows = []
    for name, (address, size) in sorted(pool.items(), key=lambda kv: kv[1][0]):
        word = data[address:address + 4]
        rows.append(
            dict(
                address=address,
                name=name,
                size=size,
                raw=data[address:address + size].hex(),
                first=first.get(address),
                value="%g" % struct.unpack(">f", word)[0] if len(word) == 4 else "",
                magic=word == MAGIC_HI,
            )
        )
    return functions, rows


def source_object(build: Path, unit_name: str) -> Path:
    rel = Path(unit_name)
    if rel.suffix == ".c":
        rel = rel.with_suffix(".o")
    return build / "src" / rel


def format_value(row):
    if row is None:
        return "-"
    raw = row["raw"]
    words = [raw[i:i + 8] for i in range(0, len(raw), 8)]
    if row["size"] == 4:
        return f"{row['value']} {words[0]}"
    return " ".join(words)


def format_first(functions, row):
    if row is None:
        return "-"
    index = row["first"]
    if index is None:
        return "-"
    return f"{index}:{functions[index][1]}"


def semantic_name(name: str) -> bool:
    return not (name.startswith("@") or name.startswith("lbl_") or name == ".hidden")


def sweep(args, root, build, objdump, objcopy, tmp):
    units = json.load(open(build / "config.json"))["units"]
    flagged = []
    for unit in units:
        obj = root / unit["object"]
        if not obj.exists():
            continue
        result = unit_rows(objdump, objcopy, obj, tmp)
        if result is None:
            continue
        functions, rows = result
        used = [r for r in rows if r["first"] is not None]
        head = 0
        while head < len(used) and any(
            later["first"] < used[head]["first"] for later in used[head + 1:]
        ):
            head += 1
        inversions = []
        best = -1
        for row in used[head:]:
            if row["first"] < best:
                inversions.append(row)
            best = max(best, row["first"])
        if head or inversions:
            flagged.append((unit["name"], len(functions), len(rows), head, inversions))
    print("%-52s %5s %5s %5s %5s" % ("unit", "fns", "pool", "head", "inv"))
    for name, nfn, npool, head, inversions in sorted(
        flagged, key=lambda f: -(f[3] + len(f[4]))
    ):
        print("%-52s %5d %5d %5d %5d" % (name, nfn, npool, head, len(inversions)))
    print()
    print(f"{len(flagged)} units carry a head block and/or a creation-order inversion.")
    print("head  = pool words ahead of the first function's own literals")
    print("        (file-scope consts, or another TU's data if the claim starts early)")
    print("inv   = a word first used earlier than a word before it => claim spans >1 TU")


def unclaimed(args, root, build, objdump, objcopy, tmp):
    units = json.load(open(build / "config.json"))["units"]
    owner: dict[str, str] = {}
    blobs: dict[str, dict] = {}
    for unit in units:
        obj = root / unit["object"]
        if not obj.exists() or "sdata2" not in unit["name"]:
            continue
        if not unit["name"].startswith("auto_"):
            continue
        data = section(objcopy, obj, ".sdata2", tmp)
        _, pool = symbols(objdump, obj)
        base = int(unit["name"].split("_")[2], 16)
        entries = []
        for name, (address, size) in sorted(pool.items(), key=lambda kv: kv[1][0]):
            word = data[address:address + 4]
            entries.append(
                dict(name=name, address=base + address, size=size,
                     value="%g" % struct.unpack(">f", word)[0] if len(word) == 4 else "")
            )
            owner[name] = unit["name"]
        blobs[unit["name"]] = dict(base=base, size=len(data), entries=entries, users={})
    for unit in units:
        obj = root / unit["object"]
        if not obj.exists() or unit.get("autogenerated"):
            continue
        for _, symbol, _ in text_relocations(objdump, obj):
            if symbol in owner:
                blobs[owner[symbol]]["users"].setdefault(symbol, set()).add(unit["name"])
    total = shared = sole = 0
    print("%-12s %6s  %s" % ("base", "size", "consumers"))
    for blob in sorted(blobs.values(), key=lambda b: b["base"]):
        consumers = set()
        for names in blob["users"].values():
            consumers |= names
        total += blob["size"]
        cross = sorted(
            s for s, u in blob["users"].items() if len(u) > 1 and s.startswith("lbl_")
        )
        if cross:
            shared += blob["size"]
        elif len(consumers) == 1:
            sole += blob["size"]
        print("%-12s %6d  %s%s" % (
            hex(blob["base"]), blob["size"], ", ".join(sorted(consumers)) or "(none)",
            "   ONE-TU-PROOF: " + ", ".join(cross[:6]) if cross else ""))
    print()
    print(f"unclaimed .sdata2 total {total} B; "
          f"{shared} B behind proven merged TUs, {sole} B sole-consumer")


def detail(args, root, build, objdump, objcopy, tmp):
    units = json.load(open(build / "config.json"))["units"]
    for unit in units:
        if unit["name"] != args.unit:
            continue
        obj = root / unit["object"]
        result = unit_rows(objdump, objcopy, obj, tmp)
        if result is None:
            raise SystemExit(
                f"{args.unit} carves no .sdata2 - its pool is unclaimed, see --unclaimed"
            )
        functions, rows = result
        for row in rows:
            index = row["first"]
            fn = functions[index][1] if index is not None else "-"
            print("%08x %-24s sz=%d %14s  %-3s %s" % (
                row["address"], row["name"], row["size"], row["value"],
                index if index is not None else "", fn))
        return
    raise SystemExit(f"unit not found: {args.unit}")


def compare_src(args, root, build, objdump, objcopy, tmp):
    units = json.load(open(build / "config.json"))["units"]
    for unit in units:
        if unit["name"] != args.unit:
            continue
        retail_obj = root / unit["object"]
        src_obj = source_object(build, unit["name"])
        if not src_obj.exists():
            raise SystemExit(f"built source object not found: {src_obj}")
        retail = unit_rows(objdump, objcopy, retail_obj, tmp)
        source = unit_rows(objdump, objcopy, src_obj, tmp)
        if retail is None:
            raise SystemExit(f"{args.unit} carves no retail .sdata2")
        if source is None:
            raise SystemExit(f"{args.unit} built source object has no .sdata2")
        retail_functions, retail_rows = retail
        source_functions, source_rows = source
        width = max(len(retail_rows), len(source_rows))
        print(f"# .sdata2 retail/source compare: {args.unit}")
        print("%4s  %-34s %-20s %-28s | %-34s %-20s %-28s  %s" %
              ("idx", "retail", "r-value/raw", "r-first", "source", "s-value/raw", "s-first", "mark"))
        for i in range(width):
            r = retail_rows[i] if i < len(retail_rows) else None
            s = source_rows[i] if i < len(source_rows) else None
            r_name = f"+{r['address']:04x} {r['name']}" if r is not None else "-"
            s_name = f"+{s['address']:04x} {s['name']}" if s is not None else "-"
            mark = ""
            if r is None or s is None:
                mark = "COUNT"
            elif r["raw"] != s["raw"]:
                mark = "RAW"
            elif r["name"] != s["name"]:
                mark = "NAME"
            print("%4d  %-34s %-20s %-28s | %-34s %-20s %-28s  %s" %
                  (i, r_name[:34], format_value(r)[:20], format_first(retail_functions, r)[:28],
                   s_name[:34], format_value(s)[:20], format_first(source_functions, s)[:28], mark))
        return
    raise SystemExit(f"unit not found: {args.unit}")


def compare_src_sweep(args, root, build, objdump, objcopy, tmp):
    units = json.load(open(build / "config.json"))["units"]
    rows = []
    for unit in units:
        if unit.get("autogenerated"):
            continue
        retail_obj = root / unit["object"]
        src_obj = source_object(build, unit["name"])
        if not retail_obj.exists() or not src_obj.exists():
            continue
        retail = unit_rows(objdump, objcopy, retail_obj, tmp)
        source = unit_rows(objdump, objcopy, src_obj, tmp)
        if retail is None or source is None:
            continue
        _, retail_rows = retail
        _, source_rows = source
        width = max(len(retail_rows), len(source_rows))
        count = raw = name = semantic = 0
        for i in range(width):
            r = retail_rows[i] if i < len(retail_rows) else None
            s = source_rows[i] if i < len(source_rows) else None
            if r is None or s is None:
                count += 1
            elif r["raw"] != s["raw"]:
                raw += 1
            elif r["name"] != s["name"]:
                name += 1
                if semantic_name(r["name"]):
                    semantic += 1
        if count or raw or name:
            rows.append((unit["name"], len(retail_rows), len(source_rows), count, raw, name, semantic))

    print("%-56s %5s %5s %5s %5s %5s %5s" % ("unit", "ret", "src", "count", "raw", "name", "sem"))
    for name, nret, nsrc, count, raw, name_only, semantic in sorted(
        rows, key=lambda row: (row[3], row[4], -row[6], -row[5], row[0])
    ):
        print("%-56s %5d %5d %5d %5d %5d %5d" % (name, nret, nsrc, count, raw, name_only, semantic))
    print()
    print(f"{len(rows)} source-built units have .sdata2 count, raw, or name drift.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-v", "--version", default="GSAE01")
    parser.add_argument("--unclaimed", action="store_true")
    parser.add_argument("--unit")
    parser.add_argument("--compare-src", action="store_true")
    parser.add_argument("--compare-src-sweep", action="store_true")
    args = parser.parse_args()
    if args.compare_src and not args.unit:
        parser.error("--compare-src requires --unit")
    if args.compare_src_sweep and args.unit:
        parser.error("--compare-src-sweep does not take --unit")
    root = Path(__file__).resolve().parent.parent
    build = root / "build" / args.version
    objdump = root / "build/binutils/powerpc-eabi-objdump"
    objcopy = root / "build/binutils/powerpc-eabi-objcopy"
    tmp = Path(tempfile.mkdtemp())
    if args.compare_src:
        compare_src(args, root, build, objdump, objcopy, tmp)
    elif args.compare_src_sweep:
        compare_src_sweep(args, root, build, objdump, objcopy, tmp)
    elif args.unit:
        detail(args, root, build, objdump, objcopy, tmp)
    elif args.unclaimed:
        unclaimed(args, root, build, objdump, objcopy, tmp)
    else:
        sweep(args, root, build, objdump, objcopy, tmp)


if __name__ == "__main__":
    main()
