from __future__ import annotations

import argparse
import csv
import re
import struct
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from romlist_audit import decompress_zlb, load_object_names, load_object_remap


TRIGGER_NAMES = {
    "TrigArea",
    "TrigBits",
    "TrigButt",
    "TrigCrve",
    "TrigCyl",
    "TrigPln",
    "TrigPnt",
    "TriggSetp",
    "TrigTime",
}

COMMAND_NAMES = {
    0x00: "no-op",
    0x03: "retail no-op",
    0x04: "object SFX",
    0x06: "triggered camera action",
    0x08: "environment/draw mode",
    0x0A: "environment effect",
    0x0B: "object sequence",
    0x0D: "lighting action",
    0x12: "GameBit write",
    0x13: "object group on",
    0x14: "object group off",
    0x18: "map act",
    0x1A: "other-map group on",
    0x1B: "other-map group off",
    0x1C: "day/environment flags",
    0x1E: "other-map act",
    0x22: "object group toggle",
    0x27: "map data load",
    0x28: "map data unload",
    0x2A: "level lock",
    0x2B: "level unlock",
}

HIGH_INTEREST_NOTES = {
    ("clouddungeon", 2): ("collision_bypass", "CFPrisonDoor; strong mechanics, but this Krystal/no-Tricky area likely lacks the known storage setup."),
    ("clouddungeon", 3): ("collision_bypass", "CFPrisonDoor; strong mechanics, but this Krystal/no-Tricky area likely lacks the known storage setup."),
    ("clouddungeon", 7): ("collision_bypass", "CFDungeonBlock reloads at retail position; this Krystal/no-Tricky area likely lacks the known storage setup."),
    ("dfptop", 4): ("persistent_edge", "One-way GameBit 0x9D1 plane near the floor-bar/lightning puzzle."),
    ("dfptop", 5): ("persistent_edge", "One-way GameBit 0x5E3 plane plus a lighting transition."),
    ("fortress", 0): ("persistent_edge", "Paired GameBit 0x5A boundary in the door/light-wall/lever cluster."),
    ("fortress", 10): ("persistent_edge", "One-way GameBit 0x320 plane near sequence/combat/light-pillar actors."),
    ("fortress", 100): ("barrier_timing", "TrigBits requests SH_Portcull closure through 0x8FC; no usable camera-storage setup is currently known in this area."),
    ("hollow2", 10): ("persistent_edge", "Paired GameBit 0xD35 boundary in a killer-mushroom combat room."),
    ("kraztest", 32): ("persistent_edge", "Sets GameBit 0x7E7 from either plane leg; a fully missed traversal leaves it unset."),
    ("kraztest", 35): ("persistent_edge", "Sets GameBit 0x7E8 from either plane leg; a fully missed traversal leaves it unset."),
    ("kraztest", 73): ("warp_suppress", "Transporter logic disappears while camera-resident object is absent."),
    ("moonpass", 188): ("warp_suppress", "MagicCaveTop stages a map and warp; free tears down a staged destination."),
    ("snowmines2", 4): ("event_abort_retry", "DIM2SeqObject; unload can interrupt its sequence before persistent effects."),
    ("snowmines2", 13): ("collision_bypass", "WallAnimator for GameBit 0x233; free does not grant completion, so the solid wall can vanish transiently."),
    ("snowmines2", 24): ("persistent_edge", "One-way GameBit 0x262 plane beside the WallAnimator/explosion cluster."),
    ("snowmines2", 31): ("group_state", "Inverse group-0/group-3 phase boundary; broad state change and redundant writers."),
    ("snowmines2", 36): ("encounter_absent_no_credit", "DIM2PrisonMammoth has an empty free callback; absence grants no completion."),
    ("snowmines2", 37): ("event_abort_retry", "DIM2SeqObject; unload can interrupt its sequence before persistent effects."),
    ("swapcircle", 15): ("persistent_edge", "Exit clears GameBit 0x7B; apparent group commands have dormant direction flags."),
    ("temple", 4): ("parity_hazard", "Toggles VFP groups 6, 8, and 11; tested and functionally low-value."),
    ("temple", 6): ("parity_hazard", "Toggles GameBit 0xD44 on both plane legs."),
    ("temple", 8): ("platform_absent", "VFPLift1 disappears; likely shaft/OOB risk rather than completion."),
    ("temple", 15): ("persistent_edge", "One-way GameBit 0x541 plane beside fuel cell/soldier/transporter actors."),
    ("temple", 34): ("group_state", "Group 8 off/on streamer; tested and functionally low-value."),
    ("temple", 35): ("collision_puzzle_bypass", "Clean group-13 statue-puzzle enable; confirmed useful cam-lock skip."),
    ("temple", 36): ("parity_hazard", "Toggles VFP groups 6 and 8; apparent group-13 commands are dormant."),
    ("warlock", 8): ("unknown_controller", "WM_Wallpower controller; cheap range but collision/state behavior is unresolved."),
    ("warlock", 11): ("companion_edge", "Tricky-targeted one-way GameBit 0x370 plane."),
    ("warlock", 12): ("persistent_edge", "One-way GameBit 0x222 plane in a combat-wall/guard region."),
}

SOURCE_CHECKS = [
    (
        "Camera-driven map streaming",
        "src/main/dll/dll_bb.c; src/main/shader.c",
        "camcontrol_applyState / loadMapForCameraPos",
        "Every camera commit recenters the 16x16 streamed map-block window from camera XYZ, then object residency runs. A displaced camera can retain remote geometry while Fox's geometry/collision is absent.",
        "critical",
    ),
    (
        "Residency load",
        "src/main/shader.c",
        "objShouldLoad",
        "Selects Fox only for flag 0x04; otherwise uses the current view/load-center position and bound*8.",
        "critical",
    ),
    (
        "Residency unload",
        "src/main/rcp_dolphin.c",
        "objShouldUnload",
        "Mirrors center selection, honors group/owner pins, and unloads beyond runtime radius + 40.",
        "critical",
    ),
    (
        "Plane crossing",
        "src/main/dll/dll_80198a00.c",
        "fn_80198DE8",
        "Tests the previous-to-current target segment against a finite plane; missed movement is not replayed.",
        "critical",
    ),
    (
        "Trigger cleanup",
        "src/main/dll/dll_0126_trigger.c",
        "Trigger_free",
        "Stops owned SFX but does not synthesize an exit leg or replay a missed command.",
        "critical",
    ),
    (
        "Untargeted staff projectile origin",
        "src/main/dll/player.c",
        "staffShootFireball / fn_802AA014",
        "Untargeted projectiles allocate at current camera XYZ and derive velocity from camera orientation/FOV. A stored camera can therefore originate a hit remotely.",
        "high_remote_hit",
    ),
    (
        "Arwing trace origin",
        "src/main/dll/ARW/dll_029A_arwarwing.c",
        "arwarwing_SeqFn / arwarwing_hitDetect",
        "A sequence snapshots camera position/orientation and later transforms the Arwing trace origin from it.",
        "high_hit_detection",
    ),
    (
        "Tricky warp visibility",
        "src/main/dll/dll_0100_trickywarp.c",
        "TrickyWarp_update",
        "Permits companion relocation only when the warp host is outside the view frustum.",
        "investigate",
    ),
    (
        "Door side routing",
        "src/main/dll/dll_00F4_doorf4.c",
        "DoorF4 update events",
        "Code chooses a side GameBit from the camera side of a door plane, but observed retail placements have zero masks or disabled side bits.",
        "inactive_retail",
    ),
    (
        "Camera-target trigger mode",
        "src/main/dll/dll_0126_trigger.c",
        "Trigger_hitDetect target kind 2",
        "The interpreter can target the camera itself, but no observed retail trigger placement uses target kind 2.",
        "inactive_retail",
    ),
    (
        "Proximity mine cull branch",
        "src/main/proximitymine_update.c",
        "ProximityMine_update",
        "Camera-derived opacity selects a path point versus target-root attack anchor; object is runtime-spawned and situational.",
        "investigate",
    ),
    (
        "DIM Tricky LOS",
        "src/main/dll/DIM/dll_019E_dim_tricky.c",
        "DIMTricky_render",
        "Uses camera distance and voxel LOS to keep/free a visibility effect source.",
        "presentation",
    ),
    (
        "Combat-source visuals",
        "src/main/dll/dll_02B1_cmbsrc.c",
        "cmbsrc_updateVisuals",
        "Camera distance gates glow/effect rendering, not encounter completion or spawning.",
        "presentation",
    ),
    (
        "Object render fade",
        "src/main/shader.c",
        "object visibility path",
        "Camera distance fades/culls rendered models; object logic remains separate.",
        "presentation",
    ),
    (
        "Explosion feedback",
        "src/main/dll/objfx.c",
        "camera-distance feedback paths",
        "Attenuates camera shake, rumble, and effects by camera distance.",
        "presentation",
    ),
]

DIRECT_SOURCE_PATTERNS = (
    "Camera_DistanceToCurrentViewPosition",
    "ViewFrustum_IsSphereVisible",
    "Camera_GetCurrentViewSlot",
)


@dataclass
class Placement:
    map_name: str
    index: int
    canonical_id: int
    name: str
    flags: int
    bound: int
    x: float
    y: float
    z: float
    unique_id: int
    raw_tail: bytes

    @property
    def load_radius(self) -> int:
        return self.bound * 8

    @property
    def unload_radius(self) -> int:
        return self.load_radius + 40

    @property
    def is_group_managed(self) -> bool:
        return bool(self.flags & 0x10)

    @property
    def is_explicit_camera(self) -> bool:
        return bool(self.flags & 0x08) and not bool(self.flags & 0x37)

    @property
    def is_camera_fallback(self) -> bool:
        return not bool(self.flags & 0x37)


def find_default_files_root(repo_root: Path) -> Path:
    candidates = (repo_root / "orig/GSAE01/files", repo_root / "orig/GSAE01_rev1/files")
    for candidate in candidates:
        if (candidate / "OBJECTS.bin").exists() and any(candidate.glob("*.romlist.zlb")):
            return candidate
    return candidates[0]


def read_placements(files_root: Path) -> list[Placement]:
    names = load_object_names(files_root)
    remap = load_object_remap(files_root)
    placements: list[Placement] = []
    for path in sorted(files_root.glob("*.romlist.zlb")):
        payload = decompress_zlb(path)
        offset = 0
        index = 0
        while offset < len(payload):
            object_id, size_words, _ = struct.unpack_from(">hBB", payload, offset)
            record = payload[offset : offset + size_words * 4]
            canonical_id = remap.get(object_id, object_id)
            x, y, z = struct.unpack_from(">fff", record, 8)
            placements.append(
                Placement(
                    map_name=path.name.removesuffix(".romlist.zlb"),
                    index=index,
                    canonical_id=canonical_id,
                    name=names.get(canonical_id, f"obj_{canonical_id:04X}"),
                    flags=record[4],
                    bound=record[6],
                    x=x,
                    y=y,
                    z=z,
                    unique_id=struct.unpack_from(">I", record, 0x14)[0],
                    raw_tail=record[0x18:],
                )
            )
            offset += size_words * 4
            index += 1
    return placements


def command_words(placement: Placement) -> list[bytes]:
    if placement.name not in TRIGGER_NAMES:
        return []
    return [placement.raw_tail[i : i + 4] for i in range(0, min(32, len(placement.raw_tail)), 4)]


def describe_command(word: bytes) -> str:
    if len(word) != 4 or word == b"\0\0\0\0":
        return ""
    flags, opcode = word[0], word[1]
    param = int.from_bytes(word[2:4], "big")
    directions = []
    if flags & 0x01:
        directions.append("enter")
    if flags & 0x02:
        directions.append("exit")
    if flags & 0x10:
        directions.append("unconditional")
    if not directions:
        directions.append("dormant")
    opname = COMMAND_NAMES.get(opcode, f"op{opcode:02X}")
    if opcode == 0x12:
        bit = param & 0x3FFF
        action = ("clear", "set", "toggle", "rewrite current")[(param >> 14) & 3]
        return f"{'/'.join(directions)} {action} GameBit 0x{bit:X} [{word.hex().upper()}]"
    return f"{'/'.join(directions)} {opname} 0x{param:X} [{word.hex().upper()}]"


def classify_placement(placement: Placement) -> tuple[str, str]:
    key = (placement.map_name, placement.index)
    if key in HIGH_INTEREST_NOTES:
        return HIGH_INTEREST_NOTES[key]
    name = placement.name.lower()
    if placement.name in TRIGGER_NAMES:
        live = [word for word in command_words(placement) if len(word) == 4 and (word[0] & 0x13)]
        opcodes = {word[1] for word in live}
        if opcodes & {0x13, 0x14, 0x1A, 0x1B, 0x22}:
            return "group_state", "Object-group state writer; establish incoming state and redundant writers."
        if 0x12 in opcodes:
            return "persistent_edge", "GameBit writer; a missed plane leg can preserve stale persistent state."
        if opcodes <= {0x00, 0x03, 0x04, 0x06, 0x08, 0x0A, 0x0D, 0x1C}:
            return "presentation", "Camera, lighting, audio, environment, or no-op commands only."
        return "event_abort_retry", "Stateful trigger; inspect persistent inputs and reload behavior."
    if "door" in name or "wallanim" in name or "dungeonbl" in name:
        return "collision_bypass", "Physical object may disappear transiently; completion is not implied."
    if "warp" in name or "transport" in name or "magiccavet" in name:
        return "warp_suppress", "Absence can suppress a warp host or staged transition."
    if "seq" in name:
        return "event_abort_retry", "Stateful event object; inspect persistent bits and reload behavior."
    if any(token in name for token in ("enemy", "sharpclaw", "hagabon", "mammoth", "kaldachom", "killer")):
        return "encounter_absent_no_credit", "Actor absence normally does not grant kill/progression credit."
    if any(token in name for token in ("lift", "platform", "puzzle", "statue", "stepping", "vine", "crystal")):
        return "puzzle_softlock_risk", "Removing the actor may expose geometry but can also remove required progression."
    if any(token in name for token in ("fx", "dust", "flow", "cmbsrc", "texscroll", "fog", "sfx", "grass", "tree")):
        return "render_fx", "Primarily presentation or ambient effects."
    if placement.name in {"curve", "setuppoint", "checkpoint4", "sideload"}:
        return "route_metadata", "Structural/route metadata; not necessarily instantiated as a normal GameObject."
    return "unclassified", "Needs class-source review."


def exploit_rank(category: str) -> int:
    ranks = {
        "collision_puzzle_bypass": 0,
        "collision_bypass": 1,
        "barrier_timing": 1,
        "persistent_edge": 2,
        "companion_edge": 2,
        "parity_hazard": 3,
        "group_state": 3,
        "warp_suppress": 3,
        "unknown_controller": 4,
        "event_abort_retry": 5,
        "platform_absent": 5,
        "encounter_absent_no_credit": 6,
        "puzzle_softlock_risk": 6,
        "unclassified": 7,
        "route_metadata": 8,
        "render_fx": 9,
        "presentation": 10,
    }
    return ranks.get(category, 7)


def source_hits(repo_root: Path) -> list[tuple[str, int, str]]:
    hits: list[tuple[str, int, str]] = []
    src_root = repo_root / "src/main"
    regex = re.compile("|".join(re.escape(pattern) for pattern in DIRECT_SOURCE_PATTERNS))
    for path in sorted(src_root.rglob("*.c")):
        for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if regex.search(line) and not re.match(r"\s*(?:int|f32|void|CameraViewSlot\*)\s+(?:" + "|".join(DIRECT_SOURCE_PATTERNS) + r")\s*\(", line):
                hits.append((path.relative_to(repo_root).as_posix(), line_no, line.strip()))
    return hits


def markdown_report(repo_root: Path, files_root: Path, placements: list[Placement]) -> str:
    explicit = [placement for placement in placements if placement.is_explicit_camera]
    fallback = [placement for placement in placements if placement.is_camera_fallback]
    trigger_entries = [placement for placement in explicit if placement.name in TRIGGER_NAMES]
    type_counts = Counter((placement.canonical_id, placement.name) for placement in explicit)
    map_counts = Counter(placement.map_name for placement in explicit)
    high_interest = []
    for placement in explicit:
        category, note = classify_placement(placement)
        if (placement.map_name, placement.index) in HIGH_INTEREST_NOTES:
            high_interest.append((exploit_rank(category), placement, category, note))
    high_interest.sort(key=lambda item: (item[0], item[1].map_name, item[1].index))

    lines = [
        "# Camera range and residency catalog",
        "",
        "> Generated by `python tools/orig/camera_range_catalog.py`. Do not hand-edit generated tables.",
        "",
        "## Scope and provenance",
        "",
        f"- Retail placement source: `{files_root.relative_to(repo_root).as_posix()}`.",
        f"- Romlist placements scanned: {len(placements):,}.",
        f"- Explicit camera-authored ranged placements: {len(explicit):,} across {len(map_counts)} maps and {len(type_counts)} object classes.",
        f"- All placements that fall through to the view-center distance path: {len(fallback):,}. This broader number includes default-flag and structural records whose class may bypass ordinary GameObject residency.",
        "- Active EN v1.0 extracted files are preferred when present. This checkout currently falls back to EN rev1; high-interest trigger records were also observed unchanged in PAL/JP, but addresses and target claims remain EN-v1.0-biased.",
        "- Source coverage combines recovered helper calls with every `Camera_GetCurrentViewSlot` call as an over-inclusive review queue. Unrecovered assembly or arithmetic reached through an opaque interface can still require manual follow-up; the report does not claim those paths are semantically understood.",
        "",
        "## Engine model",
        "",
        "`objShouldLoad` and `objShouldUnload` apply precedence before distance: act rejection, always/manual flags, object-group state (`0x10`), owner/parent pins, map-block validity, and always-resident `0x20`. A normal ranged object uses Fox only with placement flag `0x04`; otherwise it uses the current view/load-center position. Load radius is `bound * 8`; unload uses the instantiated radius plus 40 units of hysteresis.",
        "",
        "For finite trigger planes, unloading is more consequential than ordinary culling: the crossing code compares the target's previous and current positions only while the object exists. Reload seeds current state and does not replay a missed segment. Point/area/bit triggers poll and can self-heal on reload if their condition still holds.",
        "",
            "## Highest-interest placements",
        "",
        "| Placement | Object | Position | Load / unload | Flag | Why investigate |",
        "|---|---|---:|---:|---|---|",
    ]
    for _, placement, category, note in high_interest:
        lines.append(
            f"| `{placement.map_name}#{placement.index}` | `{placement.name}` | "
            f"`({placement.x:.1f}, {placement.y:.1f}, {placement.z:.1f})` | "
            f"{placement.load_radius} / {placement.unload_radius} | `{category}` | {note} |"
        )

    lines.extend(
        [
            "",
            "## DIM2 Belina cross-check",
            "",
            "The Belina reunion actors are not themselves another camera-distance trigger class. `snowmines2#318` and `snowmines2#319` are `DIM2SeqObject` records that reference `GAMEBIT_DIM_FoundBelinaTe` (`0x223`). Both use load flag `0x10`, placing them in object group 0; group-managed residency takes precedence over camera distance in `objShouldUnload`.",
            "",
            "That makes a camera-storage skip indirect: some camera-resident boundary or controller leaves group 0 disabled, and the two sequence objects consequently never instantiate. `snowmines2#31` is one camera-resident writer of group 0, but the map contains redundant group writers, so the catalog keeps the sequence objects and each writer as separate records instead of labeling #31 as the reunion trigger without a route trace.",
        ]
    )

    lines.extend(
        [
            "",
            "## Camera-resident trigger-family inventory",
            "",
            f"This is the complete explicit camera-resident trigger-family subset ({len(trigger_entries)} placements).",
            "",
            "| Placement | Type | Position | Load / unload | Commands | Classification |",
            "|---|---|---:|---:|---|---|",
        ]
    )
    for placement in sorted(trigger_entries, key=lambda item: (item.map_name, item.index)):
        commands = "; ".join(filter(None, (describe_command(word) for word in command_words(placement)))) or "none"
        category, note = classify_placement(placement)
        lines.append(
            f"| `{placement.map_name}#{placement.index}` | `{placement.name}` | "
            f"`({placement.x:.1f}, {placement.y:.1f}, {placement.z:.1f})` | "
            f"{placement.load_radius} / {placement.unload_radius} | {commands} | `{category}` — {note} |"
        )

    lines.extend(
        [
            "",
            "## Explicit camera-resident object classes",
            "",
            "The companion CSV contains every individual placement. This table is the complete class-level rollup.",
            "",
            "| Object ID | Class | Placements |",
            "|---:|---|---:|",
        ]
    )
    for (canonical_id, name), count in sorted(type_counts.items(), key=lambda item: (-item[1], item[0][0])):
        lines.append(f"| `0x{canonical_id:04X}` | `{name}` | {count} |")

    lines.extend(
        [
            "",
            "## Recovered source-level camera spatial checks",
            "",
            "| Check | Source | Function/path | Behavior | Exploit flag |",
            "|---|---|---|---|---|",
        ]
    )
    for check, source, function, behavior, flag in SOURCE_CHECKS:
        lines.append(f"| {check} | `{source}` | `{function}` | {behavior} | `{flag}` |")

    lines.extend(
        [
            "",
            "## Direct helper-call review queue",
            "",
            "These are all direct calls to the recovered distance, frustum, and current-view-slot helpers. Current-view-slot access is deliberately over-inclusive: many hits are rendering or camera construction rather than comparisons, but retaining them prevents an apparently cosmetic call from silently dropping out of the audit.",
            "",
            "| Source | Line | Expression |",
            "|---|---:|---|",
        ]
    )
    for source, line_no, snippet in source_hits(repo_root):
        lines.append(f"| `{source}` | {line_no} | `{snippet.replace('|', '&#124;')}` |")

    lines.extend(
        [
            "",
            "## Interpretation rules",
            "",
            "- `collision_bypass`: object-managed collision may disappear, but no completion bit is awarded.",
            "- `persistent_edge`, `group_state`, `parity_hazard`: a missed plane edge can outlive trigger reload; establish incoming state before testing.",
            "- `event_abort_retry`: unloading can suppress or abort an event, but persistent input bits often make it retry later.",
            "- `encounter_absent_no_credit`: enemy absence rarely synthesizes death/completion state.",
            "- `puzzle_softlock_risk`: geometry may open, but required actors also disappear.",
            "- `render_fx` and `presentation`: normally low gameplay value.",
            "- Commands whose flag byte has only `0x04`/`0x08` and no enter/exit/unconditional bit are marked dormant; opcodes `0x00` and `0x03` are no-ops in the recovered retail interpreter.",
        ]
    )
    return "\n".join(lines) + "\n"


def write_csv(path: Path, placements: list[Placement]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.writer(output)
        writer.writerow(
            (
                "map",
                "placement_index",
                "canonical_object_id",
                "object_name",
                "unique_id",
                "x",
                "y",
                "z",
                "load_flags",
                "bound",
                "load_radius",
                "unload_radius",
                "camera_authored",
                "classification",
                "note",
                "commands",
                "raw_tail",
            )
        )
        for placement in sorted(placements, key=lambda item: (item.map_name, item.index)):
            category, note = classify_placement(placement)
            commands = "; ".join(filter(None, (describe_command(word) for word in command_words(placement))))
            writer.writerow(
                (
                    placement.map_name,
                    placement.index,
                    f"0x{placement.canonical_id:04X}",
                    placement.name,
                    f"0x{placement.unique_id:08X}",
                    f"{placement.x:.6f}",
                    f"{placement.y:.6f}",
                    f"{placement.z:.6f}",
                    f"0x{placement.flags:02X}",
                    placement.bound,
                    placement.load_radius,
                    placement.unload_radius,
                    int(placement.is_explicit_camera),
                    category,
                    note,
                    commands,
                    placement.raw_tail.hex().upper(),
                )
            )


def build_argument_parser(repo_root: Path) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Catalog camera/view-centered placement residency and source checks.")
    parser.add_argument("--files-root", type=Path, default=find_default_files_root(repo_root))
    parser.add_argument("--markdown-out", type=Path)
    parser.add_argument("--csv-out", type=Path)
    return parser


def main() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    args = build_argument_parser(repo_root).parse_args()
    files_root = args.files_root.resolve()
    placements = read_placements(files_root)
    report = markdown_report(repo_root, files_root, placements)
    if args.markdown_out is None:
        print(report, end="")
    else:
        args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_out.write_text(report, encoding="utf-8")
    if args.csv_out is not None:
        write_csv(args.csv_out, [placement for placement in placements if placement.is_camera_fallback])


if __name__ == "__main__":
    main()
