#!/usr/bin/env python3
"""Compare GC/1.2.5, its patched build, and GC/1.3 without changing the build.

Records executable identities, help/default differences, small ABI controls,
and optional full-TU cMenuSetItems rematching experiments. Requires a configured
EN build and the three compilers. Generated sources and reports stay in build/.
"""

import argparse
import difflib
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

import cmenu_set_items_probe as behavior
from compiler_command import split_command_line
import flag_probe
from joint_matrices_compiler_probe import inspect_disassembly
from retail_pool_audit import SpanIndex
from version_progress import load_function_symbols, load_splits, read_dol_range, verified_dol

ROOT = Path(__file__).resolve().parents[1]
UNIT = "main/dlls/engine/0/0"
VERSIONS = ("1.2.5", "1.2.5n", "1.3")
FIXTURE = """
extern double consume(double);
extern float consume_float(float);
extern void escape(void*);
int compiler_version = __MWERKS__;
int plain_char(char value) { return value; }
double preserve(double a, double b, double c) {
    double x = consume(a);
    double y = consume(b);
    return x + y + c;
}
float preserve_float(float a, float b, float c) {
    float x = consume_float(a);
    float y = consume_float(b);
    return x + y + c;
}
int frame(void) { char buffer[9]; escape(buffer); return buffer[0]; }
"""


def run(command):
    return subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)


def pe_identity(data):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    count = struct.unpack_from("<H", data, pe + 6)[0]
    optional = struct.unpack_from("<H", data, pe + 20)[0]
    sections = []
    for index in range(count):
        offset = pe + 24 + optional + index * 40
        name = data[offset:offset + 8].rstrip(b"\0").decode("ascii")
        size, rva, raw_size, raw_offset = struct.unpack_from("<IIII", data, offset + 8)
        sections.append(dict(name=name, size=size, rva=rva, raw_size=raw_size,
                             offset=raw_offset,
                             sha256=hashlib.sha256(data[raw_offset:raw_offset + raw_size]).hexdigest()))
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                pe_timestamp=struct.unpack_from("<I", data, pe + 8)[0], sections=sections)


def patch_audit(binaries):
    """Decode only independently inspected, hash-pinned patch anchors.

    The bit's purpose is not inferred. It modifies an internal compiler record;
    treating this executable as merely a host compatibility fix is unjustified.
    """
    expected = {
        "1.2.5": "0443b5c02b1aa7b575b61e0e24c4d5ad6bed8fd54cc42de5a2204a5216001914",
        "1.2.5n": "ccf4b465cec73b5aae9c5c5543dcf8cda8a62aba246f89e2e0b200d742f2e55c",
    }
    if any(hashlib.sha256(binaries[v]).hexdigest() != digest for v, digest in expected.items()):
        return {"mapped": False}
    return {"mapped": True, "entry_va": "0x4abd9a", "stub_va": "0x506510",
            "stub_bytes": binaries["1.2.5n"][0x105910:0x105923].hex(),
            "stub": ["add esp, 0x14", "push 0x400", "call 0x49cf70", "pop ecx", "jmp 0x4abdb6"],
            "callee": ["mov edx, [0x5880c4]", "mov eax, [esp+4]", "mov ecx, [edx+0x18]",
                       "or [ecx+0x16], eax", "ret"],
            "interpretation": "Sets bit 0x400 in an internal record; semantic purpose not established."}


def retail_save_pairs():
    """Inventory a narrow prologue pattern, not arbitrary paired instructions.

    Search the first 128 bytes of each annotated function. Require stfd followed
    within two instructions by psq_st of the same nonvolatile FPR to r1+offset+8
    using GQR0. This is not an inference of source authorship or reachability.
    """
    config = ROOT / "config/GSAE01"
    dol = verified_dol(ROOT / "orig/GSAE01/sys/main.dol", config / "config.yml")
    index = SpanIndex([span for span in load_splits(config / "splits.txt")[1] if span.section == "text"])
    rows = []
    for function in load_function_symbols(config / "symbols.txt"):
        raw = read_dol_range(dol, function.address, function.size)
        words = [word for (word,) in struct.iter_unpack(">I", raw)]
        pairs = []
        for offset, word in enumerate(words[:32]):
            if word >> 26 != 54 or (word >> 16) & 31 != 1 or (word >> 21) & 31 < 14:
                continue
            displacement = (word & 0x7FFF) - (word & 0x8000)
            for following, paired in enumerate(words[offset + 1:offset + 3], offset + 1):
                paired_displacement = (paired & 0x7FF) - (paired & 0x800)
                if (paired >> 26 == 60 and (paired >> 16) & 31 == 1
                        and (paired >> 21) & 31 == (word >> 21) & 31
                        and (paired >> 12) & 7 == 0 and paired_displacement == displacement + 8):
                    pairs.append(dict(offset=following * 4, register=(paired >> 21) & 31,
                                      stfd=hex(word), psq_st=hex(paired)))
        if pairs:
            rows.append(dict(function=function.name, address=hex(function.address),
                             source=index.owner(function.address), pairs=pairs))
    return dict(sha1=hashlib.sha1(dol.data).hexdigest(), rows=rows)


def cmenu_variants(source):
    body = behavior.function(source, "cMenuSetItems")
    scalar = body.replace("int halfwordOffset[1];", "int halfwordOffset;").replace("halfwordOffset[0]", "halfwordOffset")
    indexed = re.sub(r"\*\((?:s16|int|u8)\*\)\(\(char\*\)hud \+ (?:halfwordOffset\[0\]|wordOffset|itemCount) \+ offsetof\(CMenuHud, (\w+)\)\)", r"hud->\1[itemCount]", body)
    indexed = re.sub(r"\*\(u8\*\)\(itemCount \+ offsetof\(CMenuHud, enabled\) \+ \(char\*\)hud\)", "hud->enabled[itemCount]", indexed)
    indexed = indexed.replace("*textIdCursor = halfwordOffset[0];", "*textIdCursor = 0;")
    indexed = re.sub(r"^.*(?:int halfwordOffset\[1\];|int wordOffset;|halfwordOffset\[0\] = 0;|wordOffset = 0;|wordOffset \+= 4;|halfwordOffset\[0\] \+= 2;).*\n", "", indexed, flags=re.M)
    variants = {"current": body, "scalar": scalar, "indexed": indexed}
    for name, text in list(variants.items()):
        # These locals cross different phases of the routine. Test ordinary
        # register hints, not arbitrary declaration permutations or padding.
        variants[name + "_register_count"] = text.replace("int itemCount;", "register int itemCount;")
        variants[name + "_register_item"] = text.replace("const CMenuItemDef* item;", "register const CMenuItemDef* item;")
        # Move invariant zero initialization out of the slot-clearing loop.
        if name != "indexed":
            offset = "halfwordOffset[0]" if name == "current" else "halfwordOffset"
            variants[name + "_zero_after_clear"] = text.replace(f"        {offset} = 0;\n", "").replace(f"*textIdCursor = {offset};", "*textIdCursor = 0;").replace("    itemCount = 0;", f"    {offset} = 0;\n    itemCount = 0;")
        variants[name + "_countdown_clear"] = text.replace("for (i = 0; i < CMENU_ITEM_SLOT_COUNT; i++)", "for (i = CMENU_ITEM_SLOT_COUNT; i != 0; i--)")
    return variants


def compile_case(base, output, version, name, source, extra):
    directory = output / version / name
    directory.mkdir(parents=True, exist_ok=True)
    src = directory / "0.c"
    src.write_text(source)
    obj = directory / "0.o"
    obj.unlink(missing_ok=True)
    command = list(base)
    ci = next(i for i, token in enumerate(command) if token.endswith("mwcceppc.exe"))
    command[ci] = str(ROOT / "build/compilers/GC" / version / "mwcceppc.exe")
    command[command.index("-c") + 1] = str(src)
    command[command.index("-o") + 1] = str(directory)
    command[command.index("-c"):command.index("-c")] = [*extra, "-opt", "display"]
    result = run(command)
    log = result.stdout + result.stderr
    (directory / "compile.log").write_text(log)
    row = dict(compiler=version, case=name, command=command,
               source_sha256=hashlib.sha256(source.encode()).hexdigest(),
               ok=result.returncode == 0 and "Unknown option" not in log and obj.exists())
    (directory / "command.json").write_text(json.dumps(command, indent=2) + "\n")
    if not row["ok"]:
        row["error"] = log[-2000:]
        return row
    asm = subprocess.check_output([str(ROOT / "build/binutils/powerpc-eabi-objdump"), "-drz", "-M", "gekko", str(obj)], text=True, timeout=30)
    (directory / "disassembly.txt").write_text(asm)
    row.update(inspect_disassembly(asm))
    row["object_sha256"] = hashlib.sha256(obj.read_bytes()).hexdigest()
    if name.startswith("cmenu_"):
        score, error = flag_probe.score(UNIT, str(obj))
        if error:
            raise RuntimeError(error)
        row.update(unit_fuzzy=score[0], cmenu_fuzzy=score[1]["cMenuSetItems"],
                   exact_functions=sum(value == 100 for value in score[1].values()))
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/gc125n-investigation/compiler")
    parser.add_argument("--rematch", action="store_true", help="Also compile and behavior-check C-menu source variants")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    base = [arg for arg in split_command_line(flag_probe.base_cmd(UNIT)) if arg != "-MMD"]
    identities, binaries, helps = {}, {}, {}
    compiler_index = next(i for i, arg in enumerate(base) if arg.endswith("mwcceppc.exe"))
    for version in VERSIONS:
        compiler = ROOT / "build/compilers/GC" / version / "mwcceppc.exe"
        binaries[version] = compiler.read_bytes()
        identities[version] = pe_identity(binaries[version])
        result = run([*base[:compiler_index], str(compiler), "-help", "all"])
        helps[version] = result.stdout + result.stderr
        (output / f"{version}-help.txt").write_text(helps[version])
    (output / "help.diff").write_text("".join(difflib.unified_diff(helps["1.2.5"].splitlines(True), helps["1.3"].splitlines(True), fromfile="1.2.5", tofile="1.3")))
    patch = [dict(offset=offset, old=a, new=b) for offset, (a, b) in enumerate(zip(binaries["1.2.5"], binaries["1.2.5n"])) if a != b]
    metadata = dict(commit=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, timeout=30).strip(),
                    compilers=identities, patch_bytes=patch,
                    length_difference=len(binaries["1.2.5n"]) - len(binaries["1.2.5"]),
                    patch_strings=[s.decode("ascii") for s in re.findall(rb"[ -~]{8,}", binaries["1.2.5n"]) if b"Hacked by" in s])
    metadata["patch_audit"] = patch_audit(binaries)
    (output / "identities.json").write_text(json.dumps(metadata, indent=2) + "\n")
    (output / "retail-save-pairs.json").write_text(json.dumps(retail_save_pairs(), indent=2) + "\n")
    rows = []
    profiles = {"configured": [], "no_multiple": ["-use_lmw_stmw", "off"],
                "multiple": ["-use_lmw_stmw", "on"], "peephole": ["-opt", "peephole"],
                "no_multiple_peephole": ["-use_lmw_stmw", "off", "-opt", "peephole"],
                "schedule": ["-schedule", "on"]}
    for version in VERSIONS:
        fixture_profiles = {**profiles, "o1": ["-O1"], "o4": ["-O4,p"], "proc750": ["-proc", "750"]}
        for name, flags in fixture_profiles.items():
            row = compile_case(base, output, version, "fixture_" + name, FIXTURE, flags)
            rows.append(row)
            print(version, row["case"], row["ok"], row.get("paired"), flush=True)
        default_char = list(base)
        while "-char" in default_char:
            index = default_char.index("-char")
            del default_char[index:index + 2]
        row = compile_case(default_char, output, version, "fixture_default_char", FIXTURE, [])
        rows.append(row)
    if args.rematch:
        source = (ROOT / behavior.SOURCE).read_text()
        body = behavior.function(source, "cMenuSetItems")
        for name, replacement in cmenu_variants(source).items():
            harness = "\n".join([behavior.PRELUDE, behavior.layouts(), behavior.FIXTURE,
                                 behavior.function(source, "baseline"),
                                 replacement.replace("cMenuSetItems(", "candidate(", 1), behavior.MAIN])
            host = output / (name + "-behavior.c")
            host.write_text(harness)
            for optimization in ("-O0", "-O2"):
                executable = output / (name + "-behavior")
                result = run(["clang", "-std=c99", optimization, "-fsanitize=undefined", "-DCASE_COUNT=10000", str(host), "-o", str(executable)])
                if result.returncode:
                    raise RuntimeError(result.stderr)
                result = run([str(executable)])
                if result.returncode or result.stderr:
                    raise RuntimeError(result.stdout + result.stderr)
                (output / (name + optimization + "-behavior.txt")).write_text(result.stdout)
            for version in VERSIONS:
                for profile, flags in profiles.items():
                    row = compile_case(base, output, version, "cmenu_" + name + "_" + profile, source.replace(body, replacement, 1), flags)
                    rows.append(row)
                    print(version, row["case"], row.get("cmenu_fuzzy", row.get("error")), flush=True)
                    (output / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
    (output / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
    if any(not row["ok"] for row in rows):
        raise SystemExit("Compiler probe failed; inspect results.json and compile.log")


if __name__ == "__main__":
    main()
