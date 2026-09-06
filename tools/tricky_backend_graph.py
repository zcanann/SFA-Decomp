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


def capture_graph_snapshot(memory, base, name, colored, register_class=4):
    kind, _ = register_kind(register_class)
    word = lambda address: int.from_bytes(memory(address, 4), "little")
    stage = f"BEFORE {kind} " + ("REWRITE" if colored else "SIMPLIFICATION")
    snapshot = capture_snapshot(memory, name, stage, word(base + 0x1E67B0))
    snapshot["graph_colored"] = colored
    snapshot["register_class"] = register_class
    snapshot["coloring_graph"] = capture_graph(memory, base, colored, register_class)
    # The original-count slot is independently established only for GPRs.
    # FPR captures validate physical coloring and rewrite, without claiming
    # to replay the high-degree simplification/spill policy.
    if register_class == 4:
        snapshot["available_gprs"] = [i for i, blocked in enumerate(memory(base + 0x1E2C70, 32)) if not blocked]
        snapshot["original_gpr_count"] = int.from_bytes(memory(base + 0x1DD948, 2), "little", signed=True)
    if not colored:
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


def replay_simplification(before, after, available, original_count):
    """Replay VA 0x507070 using live initial degrees and the computed weights.

    Weights are computed once at VA 0x57AB40 after the first low-degree sweep,
    without changing graph edges. This verifies worklist formation, not the
    subsequent physical-color choice, and never modifies compiler state.
    """
    validate_graph(before, colored=False)
    actual = coloring_order(after)
    if len(before) != len(after) or not 32 <= original_count <= len(before):
        raise ValueError("incompatible simplification snapshots")
    if not available or len(set(available)) != len(available) or any(not 0 <= r < 32 for r in available):
        raise ValueError("invalid available GPR set")
    if any(a["neighbors"] != b["neighbors"] for a, b in zip(before, after)):
        raise ValueError("graph edges changed during simplification")
    if any(n["prefix"][7] & 2 for n in before):
        raise ValueError("initial graph already has processed nodes")
    degree = [n["prefix"][5] for n in before]
    removed = {i for i, n in enumerate(before) if n["prefix"][7] & 4}
    order, choices = [], []

    def remove(register):
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
                remove(register)
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
            return (register >= original_count,
                    Fraction(after[register]["prefix"][3], degree[register]) if register < original_count else 0)
        selected = min(reversed(remaining), key=priority)
        choices.append({"register": selected, "degree": degree[selected], "weight": after[selected]["prefix"][3]})
        remove(selected)
    if order[::-1] != actual or degree != [n["prefix"][5] for n in after]:
        raise ValueError("replayed simplification disagrees with the live compiler graph")
    return choices
