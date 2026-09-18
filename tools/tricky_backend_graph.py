"""GC/1.3 register interference graph captured before simplification and rewriting.

The compiler's simplify/color routines (VA 0x507070/0x506F50) establish
the node widths, edge list, linked coloring order and selected physical color.
Other flags and pointers remain opaque; weights are not runtime measurements.
"""

import struct
from fractions import Fraction

from tricky_backend_ir import capture_snapshot, decode


def register_kind(register_class):
    if register_class not in (3, 4):
        raise ValueError("only GC/1.3 FPR and GPR graphs are supported")
    return ("FPR", "f") if register_class == 3 else ("GPR", "r")


def capture_simplification_policy(memory, base, register_class=4):
    """Read the active class's inputs to VA 0x507070.

    VA 0x4FCB70 counts unblocked physical registers in the class-specific
    mask. The high-degree comparisons at 0x50712C and 0x507164 both read
    0x5DD948 directly, even for FPRs. VA 0x506D58 initializes that shared
    slot from the active class's original node count; later spill
    temporaries have IDs at or above this cutoff.
    """
    register_kind(register_class)
    def read(offset, size):
        data = memory(base + offset, size)
        if len(data) != size:
            raise ValueError("short simplification policy read")
        return data

    count = int.from_bytes(read(0x1E6778 + 4 * register_class, 4), "little", signed=True)
    if count != 32:
        raise ValueError("unsupported physical register count")
    return {
        "available": [i for i, blocked in enumerate(read(0x1E2BF0 + 32 * register_class, count)) if not blocked],
        "temporary_cutoff": int.from_bytes(read(0x1DD948, 2), "little", signed=True),
    }


def capture_color_policy(memory, base, register_class=4):
    """Read the selected class's banks/reset state consumed by VA 0x506F50.

    VA 0x4CEDA0 restores the saved blocked mask and bank cursor; 0x4FCB20
    builds the initial mask, and 0x4FCAC0 enables registers in bank order.
    Both bank tables have 32 four-byte entries per class. The saved mask and
    cursor are shared by classes and must be read at the active class's hook.
    """
    register_kind(register_class)
    def read(offset, size):
        data = memory(base + offset, size)
        if len(data) != size:
            raise ValueError("short GPR color policy read")
        return data

    def bank(count_offset, table_offset):
        count = int.from_bytes(read(count_offset, 4), "little", signed=True)
        if not 0 <= count <= 32:
            raise ValueError("invalid GPR bank size")
        return list(struct.unpack("<" + "i" * count, read(table_offset, count * 4)))

    policy = {
        "initial": bank(0x1E6574 + 4 * register_class, 0x1E0BF0 + 128 * register_class),
        "reserve": bank(0x1E6794 + 4 * register_class, 0x1E0EF0 + 128 * register_class),
        "reserve_cursor": int.from_bytes(read(0x1DCA90, 2), "little", signed=True),
        "blocked": [i for i, flag in enumerate(read(0x1DCA70, 32)) if flag],
    }
    validate_color_policy(policy)
    return policy


def validate_color_policy(policy):
    for key in ("initial", "reserve", "blocked"):
        registers = policy[key]
        if len(registers) != len(set(registers)) or any(not 0 <= r < 32 for r in registers):
            raise ValueError("invalid GPR color policy registers")
    if not 0 <= policy["reserve_cursor"] <= len(policy["reserve"]):
        raise ValueError("invalid GPR reserve cursor")


def replay_coloring(before, after, policy):
    """Verify physical choices, including bank expansion, without compiler writes.

    This intentionally rejects spill/retry traces rather than predicting their
    uncaptured mutation. Excluded nodes still block an in-range raw color slot.
    """
    validate_graph(before, colored=False)
    order = coloring_order(after)
    validate_color_policy(policy)
    if len(before) != len(after) or any(a["neighbors"] != b["neighbors"] for a, b in zip(before, after)):
        raise ValueError("incompatible coloring snapshots")
    colors = [node["prefix"][6] for node in before]
    if any(color < -1 for color in colors):
        raise ValueError("unsupported negative GPR color slot")
    unavailable = set(policy["blocked"])
    enabled = set(policy["initial"]) - unavailable
    cursor = policy["reserve_cursor"]
    decisions = []
    for register in order:
        blockers = {}
        for neighbor in before[register]["neighbors"]:
            color = colors[neighbor]
            if 0 <= color < 32:
                blockers.setdefault(color, []).append(neighbor)
        free = enabled - blockers.keys()
        expanded = False
        if free:
            selected = min(free)
        else:
            while cursor < len(policy["reserve"]) and policy["reserve"][cursor] in unavailable:
                cursor += 1
            if cursor == len(policy["reserve"]):
                raise ValueError("color replay requires an uncaptured spill/retry")
            selected = policy["reserve"][cursor]
            cursor += 1
            enabled.add(selected)
            expanded = True
        if selected in blockers or selected != after[register]["prefix"][6]:
            raise ValueError(f"replayed color disagrees with the live compiler graph at GPR {register}")
        colors[register] = selected
        decisions.append({"register": register, "color": selected, "expanded_bank": expanded,
                          "blockers": blockers})
    return decisions


def capture_graph(memory, base, colored=True, register_class=4):
    register_kind(register_class)
    def read(address, size):
        data = memory(address, size)
        if len(data) != size:
            raise ValueError("short GPR graph read")
        return data

    def word(address):
        return int.from_bytes(read(address, 4), "little")

    table = word(base + 0x1E67D0)
    count = word(base + 0x1E6A7C + 4 * register_class)
    if not 32 <= count <= 4096:
        raise ValueError("invalid GPR graph size")
    nodes = []
    for register in range(count):
        address = word(table + 4 * register)
        prefix = struct.unpack("<3Ii3hHh", read(address, 26))
        if prefix[4] != register or not 0 <= prefix[8] < count:
            raise ValueError("invalid GPR graph node")
        neighbors = list(struct.unpack("<" + "h" * prefix[8], read(address + 26, 2 * prefix[8])))
        nodes.append({"address": address, "prefix": list(prefix), "neighbors": neighbors})
    validate_graph(nodes, colored=colored)
    return nodes


def capture_coalescing_policy(memory, base, register_class=4):
    """Read the interval and resulting parent map used by GC/1.3 VA 0x5794F0.

    Independently recovered in mwcc's GC_1_3/CopyCoalescing.c. The parent
    map is post-coalescing state, not a reconstruction of the input graph.
    """
    register_kind(register_class)

    def integer(offset, size, signed=False):
        raw = memory(base + offset, size)
        if len(raw) != size:
            raise ValueError("short copy-coalescing policy read")
        return int.from_bytes(raw, "little", signed=signed)

    count = integer(0x1E6A7C + 4 * register_class, 4, True)
    if not 32 <= count <= 32768:
        raise ValueError("invalid copy-coalescing register count")
    pointer = integer(0x1E01C8, 4)
    raw = memory(pointer, count * 2)
    if len(raw) != count * 2:
        raise ValueError("short copy-coalescing parent map read")
    parents = list(struct.unpack("<" + "h" * count, raw))
    if any(not 0 <= parent <= reg for reg, parent in enumerate(parents)):
        raise ValueError("copy-coalescing parent is not a minimum-number root")
    return {
        "physical_count": integer(0x1E6778 + 4 * register_class, 4, True),
        "first_eligible": integer(0x1E7258 + 2 * register_class, 2, True),
        "last_eligible": integer(0x1E66A8 + 4 * register_class, 4, True),
        "protected_gpr": integer(0x1E6CFA, 2, True),
        "parents": parents,
    }


def capture_symbol_objects(memory, snapshot):
    """Read GC/1.3 object metadata for symbolic IR operands without mutation.

    SectionCategory/ObjectName/SharedContext in the sibling mwcc project
    establish these offsets independently. Flag meanings remain numeric.
    """
    addresses = set()
    for block in snapshot["blocks"]:
        for instruction in block["instructions"]:
            for item in decode(instruction)["operands"]:
                if item["kind"] == 3:
                    address = int.from_bytes(bytes.fromhex(item["raw"])[6:10], "little")
                    if address:
                        addresses.add(address)
    objects = {}
    for address in sorted(addresses):
        raw = memory(address, 0x18)
        if len(raw) != 0x18:
            raise ValueError("short symbolic object read")
        name_pointer = int.from_bytes(raw[10:14], "little")
        name = bytearray()
        if name_pointer:
            for offset in range(256):
                char = memory(name_pointer + 10 + offset, 1)
                if len(char) != 1:
                    raise ValueError("short symbolic object name read")
                if char == b"\0":
                    break
                name.extend(char)
        info = {"name": name.decode("utf-8", "replace"), "kind": raw[2],
                "section": int.from_bytes(raw[4:6], "little", signed=True),
                "flags": int.from_bytes(raw[18:22], "little"),
                "category": int.from_bytes(raw[22:24], "little")}
        if raw[2] == 0:
            extra = memory(address + 0x1e, 0x1e)
            if len(extra) != 0x1e:
                raise ValueError("short shared-context object read")
            info.update(context=int.from_bytes(extra[:4], "little"),
                        field37=extra[0x19], cached_name38=int.from_bytes(extra[0x1a:], "little"))
        objects[str(address)] = info
    return objects


def capture_storage_modes(memory, base):
    """Read the GC/1.3 section and alias lists used by ObjGen_PPC_EABI.c."""
    def read(address, size):
        raw = memory(address, size)
        if len(raw) != size:
            raise ValueError("short storage mode read")
        return raw

    def records(offset, size, decode_record):
        address = int.from_bytes(read(base + offset, 4), "little")
        seen, result = set(), []
        while address:
            if address in seen or len(seen) >= 4096:
                raise ValueError("invalid storage mode list")
            seen.add(address)
            raw = read(address, size)
            result.append(decode_record(raw))
            address = int.from_bytes(raw[:4], "little")
        return result

    return {
        "sections": records(0x1e72ba, 12, lambda r: {
            "id": int.from_bytes(r[8:10], "little", signed=True),
            "data_mode": r[10], "function_mode": r[11]}),
        "aliases": records(0x1e6c88, 10, lambda r: {
            "id": int.from_bytes(r[8:10], "little", signed=True),
            "kind": r[4], "section": int.from_bytes(r[6:8], "little", signed=True)}),
    }


def capture_section_records(memory, base, objects):
    """Read records for captured variable names, including their shared-base owners."""
    def read(address, size):
        raw = memory(address, size)
        if len(raw) != size:
            raise ValueError("short section record read")
        return raw

    def word(address):
        return int.from_bytes(read(address, 4), "little")

    keys = {obj["cached_name38"] for obj in objects.values()
            if obj["kind"] == 0 and obj["cached_name38"]}
    address = word(base + 0x1e6a9c)
    seen, result = set(), []
    while address:
        if address in seen or len(seen) >= 65536:
            raise ValueError("invalid section record list")
        seen.add(address)
        raw = read(address, 50)
        integer = lambda offset, size=4: int.from_bytes(raw[offset:offset + size], "little")
        if integer(0) in keys:
            owner = integer(4)
            owner_base = word(owner + 20) if owner else 0
            entry = {"address": address, "key": integer(0), "owner": owner,
                     "offset": integer(12), "size": integer(16), "flags": raw[20],
                     "category": integer(44, 2), "owner_base": owner_base}
            if owner_base:
                entry.update(base_object=word(owner_base), base_enabled=word(owner_base + 8))
            result.append(entry)
        address = integer(24)
    return {"context_enabled": read(base + 0x1e7102, 1)[0],
            "records_scanned": len(seen), "records": result}


def capture_graph_snapshot(memory, base, name, colored, register_class=4):
    kind, _ = register_kind(register_class)
    word = lambda address: int.from_bytes(memory(address, 4), "little")
    stage = f"BEFORE {kind} " + ("REWRITE" if colored else "SIMPLIFICATION")
    snapshot = capture_snapshot(memory, name, stage, word(base + 0x1E67B0))
    snapshot["graph_colored"] = colored
    snapshot["register_class"] = register_class
    snapshot["coloring_graph"] = capture_graph(memory, base, colored, register_class)
    if not colored:
        snapshot["symbol_objects"] = capture_symbol_objects(memory, snapshot)
        snapshot["storage_modes"] = capture_storage_modes(memory, base)
        snapshot["section_records"] = capture_section_records(memory, base, snapshot["symbol_objects"])
        snapshot["coalescing_policy"] = capture_coalescing_policy(memory, base, register_class)
        snapshot["simplification_policy"] = capture_simplification_policy(memory, base, register_class)
        snapshot["color_policy"] = capture_color_policy(memory, base, register_class)
    return snapshot


def validate_graph(nodes, colored=True):
    addresses = [n["address"] for n in nodes]
    if len(set(addresses)) != len(nodes) or 0 in addresses:
        raise ValueError("duplicate or null graph node address")
    for register, node in enumerate(nodes):
        p, neighbors = node["prefix"], node["neighbors"]
        if len(p) != 9 or p[4] != register or p[8] != len(neighbors):
            raise ValueError("inconsistent GPR graph node")
        if len(set(neighbors)) != len(neighbors) or register in neighbors:
            raise ValueError("duplicate or self interference edge")
        if colored and not (p[7] & 4) and not 0 <= p[6] < 32:
            raise ValueError("invalid physical GPR color")
        for neighbor in neighbors:
            if not 0 <= neighbor < len(nodes):
                raise ValueError("interference edge outside graph")
            other = nodes[neighbor]
            if register not in other["neighbors"]:
                raise ValueError("asymmetric interference edge")
            # Bit 4 nodes are excluded from the simplify loop at VA 0x5070AF.
            if colored and not ((p[7] | other["prefix"][7]) & 4) and p[6] == other["prefix"][6]:
                raise ValueError("interfering nodes received the same physical GPR")


def coloring_order(nodes):
    """Recover the actual linked worklist, not a guessed priority sort."""
    validate_graph(nodes)
    by_address = {n["address"]: i for i, n in enumerate(nodes)}
    active = {i for i, n in enumerate(nodes) if n["prefix"][7] & 2}
    successors = {}
    for index in active:
        following = nodes[index]["prefix"][0]
        if following and (following not in by_address or by_address[following] not in active):
            raise ValueError("coloring worklist points outside active nodes")
        successors[index] = by_address[following] if following else None
    roots = active - set(successors.values())
    if not active:
        return []
    if len(roots) != 1:
        raise ValueError("coloring worklist is not one chain")
    order = []
    index = roots.pop()
    while index is not None:
        if index in order:
            raise ValueError("cyclic coloring worklist")
        order.append(index)
        index = successors[index]
    if set(order) != active:
        raise ValueError("coloring worklist does not cover active nodes")
    return order


def describe_node(nodes, register, colored=True, register_class=4):
    kind, prefix = register_kind(register_class)
    if not 0 <= register < len(nodes):
        raise ValueError(f"GPR graph index out of range: {register}")
    order = coloring_order(nodes) if colored else []
    p = nodes[register]["prefix"]
    if p[7] & 4:
        return f"virtual {kind} {register}: excluded node; raw color slot={p[6]}; flags={p[7]:#x}"
    position = order.index(register) if register in order else None
    assignment = f" -> {prefix}{p[6]}; color order={position}" if colored else " (before simplification)"
    return (f"virtual {kind} {register}{assignment}; "
            f"weight={p[3]}; neighbors={p[8]}; degree counter={p[5]}; flags={p[7]:#x}")


def validate_rewrite(before, final):
    """Check colors against surviving IR records, including call clobber operands.

    Address reuse is possible: only correlate unchanged opcode/line/block keys.
    This checks the observed mapping, not uninterrupted source-variable identity.
    """
    nodes = before["coloring_graph"]
    register_class = before.get("register_class", 4)
    kind, _ = register_kind(register_class)
    coloring_order(nodes)
    after = {i["address"]: decode(i) for b in final["blocks"] for i in b["instructions"]}
    checked = 0
    for block in before["blocks"]:
        for instruction in block["instructions"]:
            old = decode(instruction)
            new = after.get(old["address"])
            if new is None or any(old[k] != new[k] for k in ("opcode", "line", "block")):
                continue
            if len(old["operands"]) != len(new["operands"]):
                continue
            for source, emitted in zip(old["operands"], new["operands"]):
                if source["kind"] != 0 or source["register_class"] != register_class:
                    continue
                register = source["number"]
                if not 0 <= register < len(nodes) or nodes[register]["prefix"][7] & 4:
                    raise ValueError("rewritten operand references an absent/excluded graph node")
                if (emitted["kind"] != 0 or emitted["register_class"] != register_class
                        or emitted["number"] != nodes[register]["prefix"][6]):
                    raise ValueError(f"graph color disagrees with rewritten {kind} operand")
                checked += 1
    if not checked:
        raise ValueError(f"no surviving {kind} operands to validate graph colors")
    return checked


def replay_simplification(before, after, available, temporary_cutoff, *, steps=None):
    """Replay VA 0x507070 using live initial degrees and the computed weights.

    Weights are computed once at VA 0x57AB40 after the first low-degree sweep,
    without changing graph edges. This verifies worklist formation, not the
    subsequent physical-color choice, and never modifies compiler state.
    If supplied, steps receives every removal only after replay validates.
    Fixed color aliases remain separate degree contributions; grouping them
    here explains pressure without changing the compiler's graph algorithm.
    """
    validate_graph(before, colored=False)
    actual = coloring_order(after)
    if len(before) != len(after) or not 32 <= temporary_cutoff <= len(before):
        raise ValueError("incompatible simplification snapshots")
    if not available or len(set(available)) != len(available) or any(not 0 <= r < 32 for r in available):
        raise ValueError("invalid available register set")
    if any(a["neighbors"] != b["neighbors"] for a, b in zip(before, after)):
        raise ValueError("graph edges changed during simplification")
    if any(n["prefix"][7] & 2 for n in before):
        raise ValueError("initial graph already has processed nodes")
    degree = [n["prefix"][5] for n in before]
    removed = {i for i, n in enumerate(before) if n["prefix"][7] & 4}
    order, choices, removals = [], [], []

    def remove(register, kind):
        if steps is not None:
            fixed = {}
            active = []
            for neighbor in before[register]["neighbors"]:
                node = before[neighbor]
                color = node["prefix"][6]
                if 0 <= color < 32:
                    fixed.setdefault(color, []).append(neighbor)
                elif neighbor >= 32 and neighbor not in removed:
                    active.append(neighbor)
            removals.append({"register": register, "kind": kind, "degree": degree[register],
                             "threshold": len(available), "weight": after[register]["prefix"][3],
                             "active_neighbors": active, "fixed_colors": fixed})
        removed.add(register)
        order.append(register)
        for neighbor in before[register]["neighbors"]:
            degree[neighbor] -= 1

    while True:
        changed = False
        remaining = []
        for register in range(32, len(before)):
            if register in removed:
                continue
            if degree[register] < len(available):
                remove(register, "low-degree")
                changed = True
            else:
                remaining.append(register)
        if changed:
            continue
        if not remaining:
            break
        # The compiler prepends nodes to its candidate list, so equal costs
        # favor the higher ID. Newly generated spill temporaries use FLT_MAX.
        def priority(register):
            return (register >= temporary_cutoff,
                    Fraction(after[register]["prefix"][3], degree[register]) if register < temporary_cutoff else 0)
        selected = min(reversed(remaining), key=priority)
        choices.append({"register": selected, "degree": degree[selected], "weight": after[selected]["prefix"][3]})
        remove(selected, "high-degree")
    if order[::-1] != actual or degree != [n["prefix"][5] for n in after]:
        raise ValueError("replayed simplification disagrees with the live compiler graph")
    if steps is not None:
        steps.extend(removals)
    return choices
