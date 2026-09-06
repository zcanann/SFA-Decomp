"""Decode the observed GC/1.3 backend records used by the Tricky trace probe.

This is reconstructed compiler IR, not retail debug data. Unknown fields stay
opaque. Layouts/opcodes are specific to the hash-checked compiler capture profile.
"""

from __future__ import annotations

import re
import struct


COMPILER_SHA256 = "4e502c38465500d4fda8d966b268151a6c74c730508e3d9b7efd23d1a6083715"


# Verified by aligning both residuals' FINAL CODE streams with their emitted ELF
# instructions. Multiple spellings are PPC disassembler aliases/prediction bits.
MNEMONICS = {
    0x00: "b", 0x01: "bl", 0x05: "beq+ beq- bgt- blt+ blt-",
    0x08: "bge- ble- bne+ bne-", 0x0B: "bdnz+ bdnz-",
    0x11: "blr", 0x12: "bctr", 0x13: "bctrl", 0x15: "lbz",
    0x17: "lbzx", 0x19: "lhz", 0x1B: "lhzx", 0x1D: "lha",
    0x22: "lwz", 0x24: "lwzx", 0x28: "stb", 0x2C: "sth",
    0x31: "stw", 0x32: "stwu", 0x3C: "add", 0x3F: "addi",
    0x42: "addis", 0x49: "mulli", 0x4A: "mullw", 0x4B: "neg",
    0x4C: "subf", 0x4F: "subfic", 0x52: "cmpwi", 0x53: "cmpw",
    0x54: "cmplwi", 0x55: "cmplw", 0x58: "ori", 0x5A: "xori",
    0x5B: "xoris", 0x5C: "and", 0x5E: "xor", 0x64: "extsb",
    0x65: "extsh", 0x66: "cntlzw", 0x67: "clrlwi rlwinm slwi srwi",
    0x6A: "slw", 0x6C: "srawi", 0x70: "crset", 0x73: "cror",
    0x75: "crclr", 0x78: "mtctr", 0x79: "mtlr", 0x81: "mflr",
    0x89: "li", 0x8A: "lis", 0x8B: "mr", 0x8E: "lfs",
    0x92: "lfd", 0x96: "stfs", 0x9A: "stfd", 0x9E: "fmr",
    0xA0: "fneg", 0xA3: "fadds", 0xA5: "fsubs", 0xA7: "fmuls",
    0xA9: "fdivs", 0xAB: "fmadds", 0xB1: "fnmsubs", 0xB7: "fctiwz",
    0xB8: "fcmpu", 0xB9: "fcmpo", 0x193: "psq_l", 0x197: "psq_st",
}


def operand(words):
    raw = struct.pack("<3I", *words)
    result = {"kind": raw[0], "raw": raw.hex()}
    if raw[0] == 0:
        result.update(register_class=raw[1], flags=int.from_bytes(raw[2:4], "little"),
                      number=int.from_bytes(raw[4:6], "little", signed=True))
    elif raw[0] == 2:
        result["value"] = int.from_bytes(raw[2:6], "little", signed=True)
    elif raw[0] == 4:
        result["label"] = int.from_bytes(raw[2:6], "little")
    return result


def decode(instruction):
    words = instruction["words"]
    if len(words) < 9 or len(words) != 9 + 3 * (words[8] >> 16):
        raise ValueError("instruction size does not match operand count")
    return {
        "address": instruction["address"], "block": words[2],
        "line": None if words[7] == 0xFFFFFFFF else words[7],
        "opcode": words[8] & 0xFFFF,
        "operands": [operand(words[i:i + 3]) for i in range(9, len(words), 3)],
    }


def capture_snapshot(memory, name, stage, head):
    """Read only evidenced record widths; reject cycles and inconsistent links."""
    def words(address, count):
        data = memory(address, count * 4)
        if len(data) != count * 4:
            raise ValueError("short IR memory read")
        return list(struct.unpack("<" + "I" * count, data))

    blocks, labels, seen = [], {}, set()

    def label(address):
        chain = set()
        while address:
            if address in chain:
                raise ValueError("cyclic label chain")
            chain.add(address)
            key = str(address)
            if key in labels:
                return
            if len(labels) >= 16384:
                raise ValueError("implausible label chain")
            labels[key] = words(address, 3)
            address = labels[key][0]

    cursor = head
    while cursor:
        if cursor in seen or len(blocks) >= 4096:
            raise ValueError("cyclic or implausible basic-block chain")
        seen.add(cursor)
        block_words = words(cursor, 11)
        label(block_words[2])
        instructions, instruction_seen = [], set()
        address = block_words[5]
        while address:
            if address in instruction_seen or len(instructions) >= 4096:
                raise ValueError("cyclic or implausible instruction chain")
            instruction_seen.add(address)
            prefix = words(address, 9)
            count = prefix[8] >> 16
            if count > 128:
                raise ValueError("implausible instruction operand count")
            instruction = {"address": address, "words": prefix + words(address + 36, 3 * count)}
            for item in decode(instruction)["operands"]:
                if item["kind"] == 4:
                    label(item["label"])
            instructions.append(instruction)
            address = prefix[0]
        blocks.append({"address": cursor, "words": block_words, "instructions": instructions})
        cursor = block_words[0]
    result = {"name": name, "stage": stage, "head": head, "blocks": blocks, "labels": labels}
    validate_snapshot(result)
    return result


def validate_snapshot(snapshot):
    blocks = snapshot["blocks"]
    addresses = {b["address"] for b in blocks}
    if len(addresses) != len(blocks) or 0 in addresses:
        raise ValueError("duplicate or null basic-block address")
    if snapshot["head"] != (blocks[0]["address"] if blocks else 0):
        raise ValueError("incorrect basic-block head")
    seen = set()
    for index, block in enumerate(blocks):
        w, instructions = block["words"], block["instructions"]
        if len(w) != 11:
            raise ValueError("incorrect basic-block width")
        if w[0] != (blocks[index + 1]["address"] if index + 1 < len(blocks) else 0):
            raise ValueError("incorrect next basic block")
        if w[1] != (blocks[index - 1]["address"] if index else 0):
            raise ValueError("incorrect previous basic block")
        if w[2] and str(w[2]) not in snapshot["labels"]:
            raise ValueError("missing block-head label")
        if (w[10] & 0xFFFF) != len(instructions):
            raise ValueError("incorrect basic-block instruction count")
        if w[5:7] != ([instructions[0]["address"], instructions[-1]["address"]] if instructions else [0, 0]):
            raise ValueError("incorrect first/last instruction")
        for j, instruction in enumerate(instructions):
            address, iw = instruction["address"], instruction["words"]
            if address in seen or not address:
                raise ValueError("duplicate or null instruction address")
            seen.add(address)
            decoded = decode(instruction)
            if decoded["block"] != block["address"]:
                raise ValueError("incorrect instruction owner")
            if iw[0] != (instructions[j + 1]["address"] if j + 1 < len(instructions) else 0):
                raise ValueError("incorrect next instruction")
            if iw[1] != (instructions[j - 1]["address"] if j else 0):
                raise ValueError("incorrect previous instruction")
            for item in decoded["operands"]:
                if item["kind"] == 4 and str(item["label"]) not in snapshot["labels"]:
                    raise ValueError("missing operand label")
    for label in snapshot["labels"].values():
        if len(label) != 3:
            raise ValueError("incorrect label width")
        if label[0] and str(label[0]) not in snapshot["labels"]:
            raise ValueError("missing next label")
        # Labels for removed blocks may survive earlier optimizer stages.
    complete = set()
    for address in snapshot["labels"]:
        chain = set()
        while address != "0" and address not in complete:
            if address in chain:
                raise ValueError("cyclic label chain")
            chain.add(address)
            address = str(snapshot["labels"][address][0])
        complete.update(chain)


def emitted_instructions(snapshot):
    validate_snapshot(snapshot)
    if snapshot["stage"] != "FINAL CODE":
        raise ValueError("only FINAL CODE can be aligned to emitted instructions")
    result = []
    blocks = {b["address"] for b in snapshot["blocks"]}
    for block in snapshot["blocks"]:
        for instruction in block["instructions"]:
            decoded = decode(instruction)
            decoded["block_id"] = block["words"][7]
            if decoded["opcode"] == 0:
                if not decoded["operands"]:
                    raise ValueError("missing unconditional branch operand")
                first = decoded["operands"][0]
                if first["kind"] != 4:
                    raise ValueError("unrecognized unconditional branch operand")
                target = snapshot["labels"][str(first["label"])][1]
                if target not in blocks:
                    raise ValueError("final branch targets an absent basic block")
                if target == block["words"][0]:
                    continue
            result.append(decoded)
    return result


def validate_alignment(snapshot, assembly, code):
    """Check opcodes, explicit GPR/FPR operands, and exact li/lis/mr encodings.

    This is deliberately not a complete PowerPC emitter or relocation decoder.
    Unsupported opcodes fail closed rather than silently aligning a shifted trace.
    """
    instructions = emitted_instructions(snapshot)
    if len(instructions) != len(assembly) or len(code) != 4 * len(instructions):
        raise ValueError("FINAL CODE and emitted instruction counts differ")
    for index, (instruction, asm) in enumerate(zip(instructions, assembly)):
        op, args = instruction["opcode"], instruction["operands"]
        if asm.split()[0] not in MNEMONICS.get(op, "").split():
            raise ValueError(f"opcode alignment failed at {index}: {op:#x} / {asm}")
        if op not in (0x01, 0x13):  # Calls also carry implicit argument/clobber operands.
            registers = [
                ({4: "r", 3: "f"}[a["register_class"]], str(a["number"]))
                for a in args if a["kind"] == 0 and a["register_class"] in (3, 4)
            ]
            # A D-form zero base is printed as (0), not (r0).
            if "(0)" in asm and registers and registers[-1] == ("r", "0"):
                registers.pop()
            if registers != re.findall(r"\b([rf])(\d+)\b", asm):
                raise ValueError(f"register alignment failed at {index}: {asm}")
        expected = None
        if op in (0x89, 0x8A, 0x8B) and len(args) < 2:
            raise ValueError("missing load/move operands")
        if op == 0x89 and (args[0]["kind"] != 0 or args[1]["kind"] != 2):
            raise ValueError("invalid immediate load operands")
        if op == 0x8A and (args[0]["kind"] != 0 or args[1]["kind"] not in (2, 3)):
            raise ValueError("invalid shifted load operands")
        if op in (0x89, 0x8A) and args[0]["kind"] == 0 and args[1]["kind"] == 2:
            if args[0]["register_class"] != 4 or not 0 <= args[0]["number"] < 32:
                raise ValueError("invalid emitted GPR")
            expected = ((14 if op == 0x89 else 15) << 26) | (args[0]["number"] << 21) | (args[1]["value"] & 0xFFFF)
        elif op == 0x8B:
            dest, source = args[:2]
            if any(a["kind"] != 0 or a["register_class"] != 4 or not 0 <= a["number"] < 32 for a in (dest, source)):
                raise ValueError("invalid emitted move registers")
            expected = (31 << 26) | (source["number"] << 21) | (dest["number"] << 16) | (source["number"] << 11) | (444 << 1)
        if expected is not None and expected != int.from_bytes(code[index * 4:index * 4 + 4], "big"):
            raise ValueError(f"operand encoding failed at {index}: {asm}")
    return instructions


def instruction_history(snapshots, final_instruction):
    """Follow an address within one function; expose absent/replaced records.

    Compiler arena addresses can be reused. This reports observed records, not a
    proof of source-variable identity across transformations. Block/line/opcode
    changes remain visible to the caller instead of being normalized away.
    """
    history = []
    for ordinal, snapshot in enumerate(snapshots):
        record = next((decode(i) for b in snapshot["blocks"] for i in b["instructions"]
                       if i["address"] == final_instruction["address"]), None)
        history.append({"stage_index": ordinal, "stage": snapshot["stage"], "record": record})
    return history


def describe(instruction):
    if instruction is None:
        return "absent"
    items = []
    for item in instruction["operands"]:
        if item["kind"] == 0:
            prefix = {4: "gpr", 3: "fpr", 1: "cr"}.get(item["register_class"], f"class{item['register_class']}:")
            items.append(f"{prefix}{item['number']}[{item['flags']:#x}]")
        elif item["kind"] == 2:
            items.append(str(item["value"]))
        elif item["kind"] == 6:
            continue
        else:
            items.append(item["raw"])
    return f"op={instruction['opcode']:#x} line={instruction['line']} " + ", ".join(items)


def immediate_commoning(instruction, bounds):
    """Observed eligibility gate, not a promise that equivalent values are found.

    GC/1.3 VA 0x5082E0 rejects li/lis in mode zero; in nonzero mode its
    destination register must lie in this inclusive range. Bounds captured
    outside the pass describe its globals, not whether that pass is running.
    Only use this on virtual-register records before register coloring.
    """
    if instruction is None or instruction["opcode"] not in (0x89, 0x8A):
        return None
    args = instruction["operands"]
    if not args or args[0]["kind"] != 0 or args[0]["register_class"] != 4:
        raise ValueError("unrecognized immediate destination")
    low, high = bounds["first_register"], bounds["last_register"]
    if low > high:
        raise ValueError("inverted immediate-commoning bounds")
    return low <= args[0]["number"] <= high
