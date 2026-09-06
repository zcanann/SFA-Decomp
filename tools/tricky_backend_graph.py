"""GC/1.3 GPR interference graph captured before simplification and rewriting.

The compiler's simplify/color routines (VA 0x507070/0x506F50) establish
the node widths, edge list, linked coloring order and selected physical color.
Other flags and pointers remain opaque; weights are not runtime measurements.
"""

import struct
from fractions import Fraction

from tricky_backend_ir import decode


def capture_graph(memory, base, colored=True):
    def read(address, size):
        data = memory(address, size)
        if len(data) != size:
            raise ValueError("short GPR graph read")
        return data

    def word(address):
        return int.from_bytes(read(address, 4), "little")

    table = word(base + 0x1E67D0)
    count = word(base + 0x1E6A8C)
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


def describe_node(nodes, register, colored=True):
    if not 0 <= register < len(nodes):
        raise ValueError(f"GPR graph index out of range: {register}")
    order = coloring_order(nodes) if colored else []
    p = nodes[register]["prefix"]
    if p[7] & 4:
        return f"virtual GPR {register}: excluded node; raw color slot={p[6]}; flags={p[7]:#x}"
    position = order.index(register) if register in order else None
    assignment = f" -> r{p[6]}; color order={position}" if colored else " (before simplification)"
    return (f"virtual GPR {register}{assignment}; "
            f"weight={p[3]}; neighbors={p[8]}; degree counter={p[5]}; flags={p[7]:#x}")


def validate_rewrite(before, final):
    """Check colors against surviving IR records, including call clobber operands.

    Address reuse is possible: only correlate unchanged opcode/line/block keys.
    This checks the observed mapping, not uninterrupted source-variable identity.
    """
    nodes = before["coloring_graph"]
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
                if source["kind"] != 0 or source["register_class"] != 4:
                    continue
                register = source["number"]
                if not 0 <= register < len(nodes) or nodes[register]["prefix"][7] & 4:
                    raise ValueError("rewritten operand references an absent/excluded graph node")
                if (emitted["kind"] != 0 or emitted["register_class"] != 4
                        or emitted["number"] != nodes[register]["prefix"][6]):
                    raise ValueError("graph color disagrees with rewritten GPR operand")
                checked += 1
    if not checked:
        raise ValueError("no surviving GPR operands to validate graph colors")
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
