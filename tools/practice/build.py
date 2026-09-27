#!/usr/bin/env python3
"""Compile the optional practice payload, make/apply a small retail ISO patch.

The normal configure.py/Ninja build is intentionally untouched. An enabled
payload is linked against symbols from a hash-verified retail DOL. The patch
contains new code and checked DOL edits, never a replacement retail executable.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[2]
VERSION = "GSAE01"
# Verified EN startup: stack top 0x803F8478, default __ArenaLo 0x803FA480.
# Both OSInit arena-low calls must reserve our space before ClearArena runs.
# Do not load a DOL section above the retail apploader's production boundary.
PAYLOAD_ADDRESS = 0x803FA480
PAYLOAD_LIMIT = PAYLOAD_ADDRESS + 0x10000
BOOT_LOAD_LIMIT = 0x80700000
MAGIC = "SFA-PRACTICE-2"


def u32(data, offset):
    return struct.unpack_from(">I", data, offset)[0]


def align(value, boundary=32):
    return (value + boundary - 1) & -boundary


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sections(data):
    return [(i, u32(data, i * 4), u32(data, 0x48 + i * 4), u32(data, 0x90 + i * 4))
            for i in range(18) if u32(data, 0x90 + i * 4)]


def dol_size(header):
    return max(off + size for _, off, _, size in sections(header))


def symbols():
    text = (ROOT / "config" / VERSION / "symbols.txt").read_text()
    result = {}
    for match in re.finditer(r"^(\w+) = \.\w+:0x([0-9A-Fa-f]+);([^\n]*)", text, re.M):
        size = re.search(r"size:0x([0-9A-Fa-f]+)", match[3])
        result[match[1]] = (int(match[2], 16), int(size[1], 16) if size else 0)
    return result


def expected_dol_hash():
    text = (ROOT / "config" / VERSION / "config.yml").read_text()
    return re.search(r"^hash: ([0-9a-f]{40})$", text, re.M)[1]


def verify_dol(data):
    actual = hashlib.sha1(data).hexdigest()
    if actual != expected_dol_hash():
        raise ValueError(f"Expected clean EN v1.0 DOL {expected_dol_hash()}, got {actual}")


def branch(source, destination):
    delta = destination - source
    if delta % 4 or not -(1 << 25) <= delta < (1 << 25):
        raise ValueError("PPC branch destination is outside the relative branch range")
    return struct.pack(">I", 0x48000001 | (delta & 0x03FFFFFC))


def direct_calls(data, target, bounds=None):
    result = []
    for slot, off, address, size in sections(data):
        if slot >= 7:
            continue
        for n in range(0, size, 4):
            pc = address + n
            if bounds and not bounds[0] <= pc < bounds[0] + bounds[1]:
                continue
            instruction = u32(data, off + n)
            if instruction & 0xFC000003 != 0x48000001:
                continue
            delta = instruction & 0x03FFFFFC
            if delta & 0x02000000:
                delta -= 0x04000000
            if (pc + delta) & 0xFFFFFFFF == target:
                result.append((off + n, pc))
    return result


def run(argv):
    subprocess.run([str(a) for a in argv], check=True, cwd=ROOT)


def tool_directory(name):
    local = ROOT / "build" / name
    if local.exists():
        return local
    gitfile = ROOT / ".git"
    if gitfile.is_file():
        gitdir = Path(gitfile.read_text().strip().removeprefix("gitdir: "))
        if not gitdir.is_absolute():
            gitdir = ROOT / gitdir
        common = gitdir / (gitdir / "commondir").read_text().strip()
        return common.resolve().parent / "build" / name
    return local


def compile_payload(out, enabled, compilers=None, binutils=None):
    out.mkdir(parents=True, exist_ok=True)
    obj = out / ("practice.o" if enabled else "practice-disabled.o")
    compilers = compilers or tool_directory("compilers")
    binutils = binutils or tool_directory("binutils")
    suffix = ".exe" if (binutils / "powerpc-eabi-nm.exe").exists() else ""
    nm_tool = binutils / ("powerpc-eabi-nm" + suffix)
    flags = ["-nodefaults", "-proc", "gekko", "-align", "powerpc", "-enum", "int",
             "-fp", "hardware", "-Cpp_exceptions", "off", "-O4,p", "-inline", "auto",
             "-nosyspath", "-RTTI", "off", "-fp_contract", "off", "-str", "reuse",
             "-char", "signed", "-sdata", "0", "-sdata2", "0", "-maxerrors", "10",
             "-i", ROOT / "include", "-DVERSION_GSAE01"]
    if enabled:
        flags += ["-DSFA_PRACTICE"]
    run([compilers / "GC/1.3/mwcceppc.exe", *flags, "-c", ROOT / "src/practice/practice.c", "-o", obj])
    nm = subprocess.check_output([str(nm_tool), "--defined-only", str(obj)], text=True)
    if not enabled:
        if nm.strip():
            raise ValueError("Disabled practice translation unit unexpectedly defines symbols")
        return b"", {}
    linker = out / "practice.ld"
    bindings = "\n".join(f"{name} = 0x{addr:08x};" for name, (addr, _) in symbols().items())
    linker.write_text(bindings + f"""
SECTIONS {{
  . = 0x{PAYLOAD_ADDRESS:08x};
  .practice : {{
    __practice_start = .;
    *(.text*) *(.rodata*) *(.data*) *(.sdata*)
    . = ALIGN(32);
    *(.bss*) *(.sbss*) *(COMMON)
    BYTE(0)
    . = ALIGN(32);
    __practice_end = .;
  }}
  /DISCARD/ : {{ *(.comment) *(.eh_frame*) *(.llvm_addrsig) }}
}}
ASSERT(__practice_end <= 0x{PAYLOAD_LIMIT:08x}, "Practice payload exceeds reservation")
__practice_limit = 0x{PAYLOAD_LIMIT:08x};
""")
    elf = out / "practice.elf"
    run([binutils / ("powerpc-eabi-ld" + suffix), "-T", linker, "-Map=" + str(out / "practice.map"), "-o", elf, obj])
    binary = out / "practice.bin"
    run([binutils / ("powerpc-eabi-objcopy" + suffix), "-O", "binary", "--only-section=.practice", elf, binary])
    nm = subprocess.check_output([str(nm_tool), "--defined-only", str(elf)], text=True)
    exports = {m[2]: int(m[1], 16) for m in re.finditer(r"^([0-9a-fA-F]+) \w (\w+)$", nm, re.M)}
    return binary.read_bytes(), exports


def make_patch(dol, payload, exports):
    verify_dol(dol)
    if not payload or len(payload) > PAYLOAD_LIMIT - PAYLOAD_ADDRESS:
        raise ValueError("Payload is empty or exceeds its reserved memory")
    edits = []
    hooks = [
        ("OSInit", "OSSetArenaLo", "Practice_SetArenaLo", 2),
        ("gameLoop", "padUpdate", "Practice_PadUpdate", 1),
        ("gameLoop", "doNothing_endOfFrame", "Practice_Draw", 1),
        ("loadNextMap", "mapReload", "Practice_WarpReload", 1),
        (None, "playerDoControls", "Practice_PlayerControls", 1),
        (None, "playerUpdateSurfaceResponse", "Practice_SurfaceResponse", 1),
        ("SaveGame_gplaySavePoint", "memcpy", "Practice_SaveCheckpointCopy", 3),
        ("SaveGame_gplaySavePoint", "mm_free", "Practice_ClearCheckpoint", 1),
        ("SaveGame_gplayRestartPoint", "mainSetBits", "Practice_RestartCheckpointBit", 2),
        ("SaveGame_gplayGotoSavegame", "loadMapForCurrentSaveGame", "Practice_GotoSaveCheckpoint", 1),
        ("SaveGame_gplayGotoRestartPoint", "loadMapForCurrentSaveGame", "Practice_GotoRestartCheckpoint", 1),
        ("SaveGame_gplayClearRestartPoint", "mm_free", "Practice_ClearCheckpoint", 1),
        ("saveGame_save", "_saveGame", "Practice_WriteSave", 1),
        ("gplaySaveGame", "_saveGame", "Practice_WriteSave", 1),
    ]
    table = symbols()
    for caller, callee, replacement, count in hooks:
        calls = direct_calls(dol, table[callee][0], table[caller] if caller else None)
        if len(calls) != count:
            raise ValueError(f"{caller} -> {callee}: expected {count} verified calls, found {len(calls)}")
        for off, pc in calls:
            edits.append({"offset": off, "before": dol[off:off+4].hex(),
                          "after": branch(pc, exports[replacement]).hex(),
                          "hook": f"{callee} -> {replacement}", "address": pc})
    slot = next(i for i in range(7) if u32(dol, 0x90 + i * 4) == 0)
    offset = align(len(dol))
    for base, value in [(0, offset), (0x48, PAYLOAD_ADDRESS), (0x90, len(payload))]:
        at = base + slot * 4
        edits.append({"offset": at, "before": dol[at:at+4].hex(), "after": struct.pack(">I", value).hex()})
    for _, _, address, size in sections(dol):
        if address < PAYLOAD_ADDRESS + len(payload) and address + size > PAYLOAD_ADDRESS:
            raise ValueError("Payload overlaps an original DOL section")
    bss, bss_size = u32(dol, 0xD8), u32(dol, 0xDC)
    if bss < PAYLOAD_ADDRESS + len(payload) and bss + bss_size > PAYLOAD_ADDRESS:
        raise ValueError("Payload overlaps original BSS")
    manifest = {"format": MAGIC, "version": VERSION, "dol_sha1": expected_dol_hash(),
            "payload_address": PAYLOAD_ADDRESS, "payload_offset": offset,
            "payload_sha256": hashlib.sha256(payload).hexdigest(), "edits": edits}
    validate_boot_layout(apply_dol(dol, manifest, payload))
    return manifest


def validate_boot_layout(dol):
    for _, _, address, size in sections(dol):
        if address < 0x80003100 or address + size > BOOT_LOAD_LIMIT:
            raise ValueError("DOL section exceeds the retail apploader's production load boundary")


def apply_dol(dol, manifest, payload):
    if manifest["format"] != MAGIC or manifest["version"] != VERSION:
        raise ValueError("Unsupported practice package")
    verify_dol(dol)
    if manifest["dol_sha1"] != expected_dol_hash() or manifest["payload_address"] != PAYLOAD_ADDRESS:
        raise ValueError("Package target does not match this release")
    if manifest["payload_offset"] != align(len(dol)) or not 0 < len(payload) <= PAYLOAD_LIMIT - PAYLOAD_ADDRESS:
        raise ValueError("Invalid payload extent")
    if hashlib.sha256(payload).hexdigest() != manifest["payload_sha256"]:
        raise ValueError("Corrupt practice payload")
    data = bytearray(dol)
    for edit in manifest["edits"]:
        off = edit["offset"]
        before, after = bytes.fromhex(edit["before"]), bytes.fromhex(edit["after"])
        if off < 0 or off + len(before) > len(dol) or len(before) != 4 or len(after) != 4 or data[off:off+4] != before:
            raise ValueError(f"Unexpected original bytes at DOL offset {off:#x}")
        data[off:off+len(after)] = after
    data.extend(bytes(manifest["payload_offset"] - len(data)))
    data.extend(payload)
    validate_boot_layout(data)
    return bytes(data)


def read_iso(iso):
    with iso.open("rb") as stream:
        header = stream.read(0x440)
        if header[:8] != b"GSAE01\x00\x00" or u32(header, 0x1C) != 0xC2339F3D:
            raise ValueError("Only an EN v1.0 GameCube ISO is supported by this release")
        dol_offset, fst_offset, fst_size = (u32(header, n) for n in (0x420, 0x424, 0x428))
        stream.seek(dol_offset)
        dol_header = stream.read(0x100)
        stream.seek(dol_offset)
        dol = stream.read(dol_size(dol_header))
        verify_dol(dol)
        stream.seek(fst_offset)
        fst = stream.read(fst_size)
        count = u32(fst, 8)
        if not 1 <= count <= fst_size // 12:
            raise ValueError("Invalid filesystem table")
        stream.seek(0x2440)
        apploader = stream.read(0x20)
        fst_reserved = max(fst_size, u32(header, 0x42C))
        occupied = [(0, 0x2440 + 0x20 + u32(apploader, 0x14) + u32(apploader, 0x18)),
                    (dol_offset, dol_offset + len(dol)), (fst_offset, fst_offset + fst_reserved)]
        if any(stop > iso.stat().st_size for _, stop in occupied):
            raise ValueError("System extent extends beyond the image")
        for i in range(1, count):
            if fst[i * 12] == 0:
                start, size = u32(fst, i * 12 + 4), u32(fst, i * 12 + 8)
                if start + size > iso.stat().st_size:
                    raise ValueError("Filesystem entry extends beyond the image")
                occupied.append((start, start + size))
        return dol, occupied


def find_disc_space(occupied, length, image_size):
    end = 0
    gaps = []
    for start, stop in sorted(occupied) + [(image_size, image_size)]:
        at = align(end, 0x8000)
        if start - at >= length:
            gaps.append((start - at, at))
        end = max(end, stop)
    if not gaps:
        raise ValueError("No unused disc extent can hold the patched executable")
    return max(gaps)[1]


def verify_unchanged_extents(iso, output, changed):
    size = iso.stat().st_size
    if output.stat().st_size != size:
        raise ValueError("Output image size changed")
    end = 0
    with iso.open("rb") as source, output.open("rb") as target:
        for start, stop in sorted(changed) + [(size, size)]:
            source.seek(end)
            target.seek(end)
            remaining = start - end
            while remaining:
                amount = min(remaining, 4 << 20)
                if source.read(amount) != target.read(amount):
                    raise ValueError("Output differs outside declared patch extents")
                remaining -= amount
            end = stop


def write_iso(iso, output, manifest, payload):
    iso, output = iso.resolve(), output.resolve()
    if output == iso or output.exists():
        raise ValueError("Output must be a NEW file; existing images are never overwritten")
    before_hash = digest(iso)
    original, occupied = read_iso(iso)
    patched = apply_dol(original, manifest, payload)
    with iso.open("rb") as stream:
        stream.seek(0x420)
        original_position = struct.unpack(">I", stream.read(4))[0]
    # Prefer replacing the logical DOL in its existing extent. Relocate only
    # when growth would overwrite the FST, apploader, or an asset.
    old_extent = (original_position, original_position + len(original))
    neighbors = [extent for extent in occupied if extent != old_extent]
    fits = original_position + len(patched) <= iso.stat().st_size and not any(
        start < original_position + len(patched) and stop > original_position
        for start, stop in neighbors)
    position = original_position if fits else find_disc_space(occupied, len(patched), iso.stat().st_size)
    output.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation is intentional: never truncate another run's output.
    with iso.open("rb") as source, output.open("xb") as target:
        shutil.copyfileobj(source, target, 4 << 20)
        target.seek(position)
        target.write(patched)
        if position != original_position:
            target.seek(0x420)
            target.write(struct.pack(">I", position))
    with output.open("rb") as stream:
        stream.seek(position)
        if stream.read(len(patched)) != patched:
            raise ValueError("Patched executable failed read-back verification")
    changed = [(position, position + len(patched))]
    if position != original_position:
        changed.append((0x420, 0x424))
    verify_unchanged_extents(iso, output, changed)
    if digest(iso) != before_hash:
        raise ValueError("Original ISO changed during generation")
    return {"input": str(iso), "output": str(output), "input_sha256": before_hash,
            "output_sha256": digest(output), "dol_offset": position, "dol_size": len(patched),
            "original_dol_offset": original_position, "dol_relocated": position != original_position,
            "changed_extents": changed, "all_other_bytes_identical": True,
            "patched_dol_sha256": hashlib.sha256(patched).hexdigest()}


def write_dol(dol, output, manifest, payload):
    """Container-independent executable replacement for image adapters."""
    patched = apply_dol(dol, manifest, payload)
    with output.open("xb") as stream:
        stream.write(patched)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["build", "apply"])
    parser.add_argument("--enable", action="store_true", help="define SFA_PRACTICE (default: disabled)")
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--iso", type=Path, help="uncompressed GameCube ISO/GCM")
    inputs.add_argument("--dol", type=Path, help="extracted main.dol; output is a patched DOL")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--patch", type=Path, help="package to create, or existing package for apply")
    parser.add_argument("--build-dir", type=Path, default=ROOT / "build/practice")
    parser.add_argument("--compilers", type=Path, help="existing decomp compiler directory")
    parser.add_argument("--binutils", type=Path, help="existing PowerPC binutils directory")
    args = parser.parse_args()
    out = args.build_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if args.command == "build":
        dol = args.dol.read_bytes() if args.dol else read_iso(args.iso)[0]
        verify_dol(dol)
        payload, exports = compile_payload(out, args.enable, args.compilers, args.binutils)
        if not args.enable:
            (out / "practice-disabled.dol").write_bytes(dol)
            print("SFA_PRACTICE disabled: no symbols, no hooks; DOL matches retail SHA-1", expected_dol_hash())
            if args.output:
                source_path = args.dol or args.iso
                with source_path.open("rb") as source, args.output.open("xb") as target:
                    shutil.copyfileobj(source, target, 4 << 20)
                if digest(source_path) != digest(args.output):
                    raise ValueError("Disabled output differs from original")
            return
        manifest = make_patch(dol, payload, exports)
        (out / "practice.dol").write_bytes(apply_dol(dol, manifest, payload))
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        patch = args.patch or out / "SFA-EN-v1.0-practice.sfapatch"
        with zipfile.ZipFile(patch, "x", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", json.dumps(manifest, indent=2))
            archive.writestr("practice.bin", payload)
        print("Created patch:", patch)
        print("Payload:", len(payload), "bytes; original addresses preserved; 64 KiB arena-low reservation")
    else:
        if not args.patch or not args.output:
            parser.error("apply requires --patch and --output")
        with zipfile.ZipFile(args.patch) as archive:
            manifest = json.loads(archive.read("manifest.json"))
            payload = archive.read("practice.bin")
    if args.output:
        if args.dol:
            write_dol(args.dol.read_bytes(), args.output, manifest, payload)
            print("Created patched DOL:", args.output)
        else:
            report = write_iso(args.iso, args.output, manifest, payload)
            (out / "iso-report.json").write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
