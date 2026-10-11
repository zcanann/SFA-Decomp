"""Find retail map-streaming transitions that may exceed the 64-block table.

The game loads every block in the new 16x16 camera neighborhood before it
releases references held by the old neighborhood.  This tool reconstructs the
referenced block IDs from MAPS.bin/MAPS.tab, globalma.bin, and TRKBLK.tab.

The report is an upper-bound candidate scan.  It does not yet reproduce
mapCheckCurBlocks or validate each ID against the two merged mod*.tab archives,
so an ID that is unavailable at runtime can appear in the reported union.
"""
from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


ROOT = Path(__file__).resolve().parents[1]
VERSIONS = ("GSAE01", "GSAE01_rev1", "GSAJ01", "GSAP01", "GSAP01_rev1")
LAYER_OFFSETS = (0, -2, -1, 1, 2)


class AssetSource(Protocol):
    def read_bytes(self, name: str) -> bytes: ...


@dataclass(frozen=True)
class ExtractedFiles:
    root: Path

    def read_bytes(self, name: str) -> bytes:
        return (self.root / name).read_bytes()


class DiscImage:
    """Small read-only GameCube FST reader; enough to avoid extracting an ISO."""

    def __init__(self, path: Path) -> None:
        self.path = path
        with path.open("rb") as stream:
            stream.seek(0x424)
            fst_offset, fst_size = struct.unpack(">II", stream.read(8))
            stream.seek(fst_offset)
            fst = stream.read(fst_size)
        entry_count = u32(fst, 8)
        strings_offset = entry_count * 12
        directories: list[tuple[str, int]] = []
        self.entries: dict[str, tuple[int, int]] = {}
        for index in range(1, entry_count):
            word, offset, size = struct.unpack_from(">III", fst, index * 12)
            while directories and index >= directories[-1][1]:
                directories.pop()
            name_offset = strings_offset + (word & 0xFFFFFF)
            name_end = fst.index(0, name_offset)
            name = fst[name_offset:name_end].decode("ascii")
            full_name = "/".join([item[0] for item in directories] + [name])
            if word >> 24:
                directories.append((name, size))
            else:
                self.entries[full_name.lower()] = (offset, size)
                self.entries.setdefault(name.lower(), (offset, size))

    def read_bytes(self, name: str) -> bytes:
        offset, size = self.entries[name.lower()]
        with self.path.open("rb") as stream:
            stream.seek(offset)
            return stream.read(size)


@dataclass(frozen=True)
class GlobalMap:
    map_id: int
    origin_x: int
    origin_z: int
    layer: int
    adjacent_1: int
    adjacent_2: int


@dataclass(frozen=True)
class MapPage:
    map_id: int
    size_x: int
    size_z: int
    local_origin_x: int
    local_origin_z: int
    min_x: int
    min_z: int
    cells: tuple[int, ...]
    cell_rects: tuple[int, ...]
    layer_rects: tuple[int, ...]

    @property
    def max_x(self) -> int:
        return self.min_x + self.size_x - 1

    @property
    def max_z(self) -> int:
        return self.min_z + self.size_z - 1


@dataclass(frozen=True)
class Neighborhood:
    center_x: int
    center_z: int
    cur_layer: int
    center_map_id: int
    loads: tuple[int, ...]

    @property
    def unique(self) -> tuple[int, ...]:
        return tuple(dict.fromkeys(self.loads))


def s16(data: bytes, offset: int) -> int:
    return struct.unpack_from(">h", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]


def load_names(files: AssetSource) -> list[str]:
    data = files.read_bytes("MAPINFO.bin")
    return [data[offset : offset + 28].split(b"\0", 1)[0].decode("ascii", "replace")
            for offset in range(0, len(data), 0x20)]


def load_global_maps(files: AssetSource) -> dict[int, GlobalMap]:
    data = files.read_bytes("globalma.bin")
    result: dict[int, GlobalMap] = {}
    for offset in range(0, len(data), 0x0C):
        origin_x, origin_z, layer, map_id, adjacent_1, adjacent_2 = struct.unpack_from(">6h", data, offset)
        if map_id < 0:
            break
        result[map_id] = GlobalMap(map_id, origin_x, origin_z, layer, adjacent_1, adjacent_2)
    return result


def load_pages(files: AssetSource, globals_by_id: dict[int, GlobalMap]) -> dict[int, MapPage]:
    maps_bin = files.read_bytes("MAPS.bin")
    maps_tab = files.read_bytes("MAPS.tab")
    result: dict[int, MapPage] = {}
    for map_id, global_map in globals_by_id.items():
        offsets = struct.unpack_from(">7I", maps_tab, map_id * 0x1C)
        size_x, size_z, local_origin_x, local_origin_z = struct.unpack_from(">4h", maps_bin, offsets[0])
        if (size_x & 0xFFFF, size_z & 0xFFFF) == (0xFACE, 0xFEED):
            continue
        count = size_x * size_z
        cells = struct.unpack_from(f">{count}I", maps_bin, offsets[1])
        cell_rects = struct.unpack_from(f">{count * 2}I", maps_bin, offsets[2])
        layer_word_count = (offsets[5] - offsets[4]) // 4
        layer_rects = struct.unpack_from(f">{layer_word_count}I", maps_bin, offsets[4])
        result[map_id] = MapPage(
            map_id=map_id,
            size_x=size_x,
            size_z=size_z,
            local_origin_x=local_origin_x,
            local_origin_z=local_origin_z,
            min_x=global_map.origin_x - local_origin_x,
            min_z=global_map.origin_z - local_origin_z,
            cells=cells,
            cell_rects=cell_rects,
            layer_rects=layer_rects,
        )
    return result


def load_trkblk(files: AssetSource) -> tuple[int, ...]:
    data = files.read_bytes("TRKBLK.tab")
    values = struct.unpack(f">{len(data) // 2}h", data)
    sentinel = values.index(-1)
    # Retail decrements the pre-sentinel count once, making the preceding entry
    # the exclusive upper block bound and all earlier entries directory bases.
    return values[:sentinel]


def map_at(pages: dict[int, MapPage], globals_by_id: dict[int, GlobalMap], x: int, z: int,
           layer: int) -> MapPage | None:
    for map_id in range(128):
        page = pages.get(map_id)
        global_map = globals_by_id.get(map_id)
        if page is None or global_map is None or global_map.layer != layer:
            continue
        if not (page.min_x <= x <= page.max_x and page.min_z <= z <= page.max_z):
            continue
        index = (x - page.min_x) + (z - page.min_z) * page.size_x
        if ((page.cells[index] >> 23) & 0xFF) != 0xFF:
            return page
    return None


def decode_rect_word(word: int) -> tuple[tuple[int, int, int, int], tuple[int, int, int, int]]:
    first = (((word >> 12) & 0xF) - 7, ((word >> 4) & 0xF) - 7,
             ((word >> 8) & 0xF) - 7, (word & 0xF) - 7)
    second = ((word >> 28) - 7, ((word >> 20) & 0xF) - 7,
              ((word >> 24) & 0xF) - 7, ((word >> 16) & 0xF) - 7)
    return first, second


def load_rects(page: MapPage, x: int, z: int, layer_index: int) -> tuple[tuple[int, int, int, int], ...]:
    index = (x - page.min_x) + (z - page.min_z) * page.size_x
    if layer_index == 0:
        first, second = decode_rect_word(page.cell_rects[index * 2])
        third, fourth = decode_rect_word(page.cell_rects[index * 2 + 1])
        return first, second, third, fourth
    cell_value = page.cells[index] & 0x7F
    if cell_value == 0x7F:
        return ()
    table_index = cell_value * 4 + layer_index - 1
    if table_index >= len(page.layer_rects):
        return ()
    first, second = decode_rect_word(page.layer_rects[table_index])
    return first, second


def block_at(pages: dict[int, MapPage], globals_by_id: dict[int, GlobalMap], trkblk: tuple[int, ...],
             x: int, z: int, layer: int) -> int | None:
    page = map_at(pages, globals_by_id, x, z, layer)
    if page is None:
        return None
    index = (x - page.min_x) + (z - page.min_z) * page.size_x
    cell = page.cells[index]
    cell_index = (cell >> 17) & 0x3F
    directory = (cell >> 23) & 0xFF
    if directory == 0xFF:
        return None
    directory = min(directory, len(trkblk) - 2)
    return min(cell_index + trkblk[directory], trkblk[-1] - 1)


def neighborhood(pages: dict[int, MapPage], globals_by_id: dict[int, GlobalMap], trkblk: tuple[int, ...],
                 center_x: int, center_z: int, cur_layer: int) -> Neighborhood | None:
    center_page = map_at(pages, globals_by_id, center_x, center_z, cur_layer)
    if center_page is None:
        return None
    marked: list[set[tuple[int, int]]] = [set() for _ in LAYER_OFFSETS]
    for layer_index in range(len(LAYER_OFFSETS)):
        for min_x, max_x, min_z, max_z in load_rects(center_page, center_x, center_z, layer_index):
            for rel_z in range(min_z, max_z + 1):
                for rel_x in range(min_x, max_x + 1):
                    cell_x = rel_x + 7
                    cell_z = rel_z + 7
                    if 0 <= cell_x < 16 and 0 <= cell_z < 16:
                        marked[layer_index].add((cell_x, cell_z))
    loads: list[int] = []
    for layer_index, cells in enumerate(marked):
        layer = cur_layer + LAYER_OFFSETS[layer_index]
        for cell_z in range(16):
            for cell_x in range(16):
                if (cell_x, cell_z) not in cells:
                    continue
                block_id = block_at(pages, globals_by_id, trkblk,
                                    center_x + cell_x - 7, center_z + cell_z - 7, layer)
                if block_id is not None:
                    loads.append(block_id)
    return Neighborhood(center_x, center_z, cur_layer, center_page.map_id, tuple(loads))


def all_neighborhoods(files: AssetSource) -> tuple[list[str], list[Neighborhood]]:
    names = load_names(files)
    globals_by_id = load_global_maps(files)
    pages = load_pages(files, globals_by_id)
    trkblk = load_trkblk(files)
    results: list[Neighborhood] = []
    for cur_layer in range(-2, 3):
        coords: set[tuple[int, int]] = set()
        for page in pages.values():
            if globals_by_id[page.map_id].layer != cur_layer:
                continue
            for z in range(page.min_z, page.max_z + 1):
                for x in range(page.min_x, page.max_x + 1):
                    coords.add((x, z))
        for x, z in sorted(coords, key=lambda item: (item[1], item[0])):
            value = neighborhood(pages, globals_by_id, trkblk, x, z, cur_layer)
            if value is not None:
                results.append(value)
    return names, results


def transition_rows(neighborhoods: list[Neighborhood], max_step: int) -> list[tuple[int, Neighborhood, Neighborhood, tuple[int, ...]]]:
    by_position = {(item.center_x, item.center_z, item.cur_layer): item for item in neighborhoods}
    rows = []
    for old in neighborhoods:
        old_unique = set(old.unique)
        for dz in range(-max_step, max_step + 1):
            for dx in range(-max_step, max_step + 1):
                if dx == 0 and dz == 0 or max(abs(dx), abs(dz)) > max_step:
                    continue
                new = by_position.get((old.center_x + dx, old.center_z + dz, old.cur_layer))
                if new is None:
                    continue
                appended = tuple(block for block in new.unique if block not in old_unique)
                union_count = len(old_unique | set(new.unique))
                if union_count > 64:
                    rows.append((union_count, old, new, appended))
    rows.sort(key=lambda row: (-row[0], abs(row[2].center_x - row[1].center_x) +
                              abs(row[2].center_z - row[1].center_z), row[1].center_z, row[1].center_x,
                              row[2].center_z, row[2].center_x))
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", choices=VERSIONS, default="GSAE01_rev1")
    parser.add_argument("--iso", type=Path, help="read assets directly from this GameCube ISO")
    parser.add_argument("--max-step", type=int, default=1,
                        help="maximum camera-grid delta per axis to compare (default: 1)")
    parser.add_argument("--map", dest="map_filter", help="case-insensitive map-name substring")
    parser.add_argument("--limit", type=int, default=50)
    args = parser.parse_args()

    files: AssetSource
    if args.iso:
        files = DiscImage(args.iso)
    else:
        files = ExtractedFiles(ROOT / "orig" / args.version / "files")
    names, neighborhoods = all_neighborhoods(files)
    if args.map_filter:
        needle = args.map_filter.lower()
        neighborhoods = [item for item in neighborhoods if needle in names[item.center_map_id].lower()]
    maximum = max(neighborhoods, key=lambda item: len(item.unique))
    print(f"{args.version}: {len(neighborhoods)} valid centers; maximum referenced neighborhood "
          f"{len(maximum.unique)} block IDs at ({maximum.center_x}, {maximum.center_z}), "
          f"layer {maximum.cur_layer}, map {maximum.center_map_id} {names[maximum.center_map_id]!r}")
    rows = transition_rows(neighborhoods, args.max_step)
    print(f"candidate transitions with >64 referenced IDs: {len(rows)} "
          "(archive availability not applied)")
    for union_count, old, new, appended in rows[:args.limit]:
        print(f"union={union_count} {names[old.center_map_id]!r} "
              f"({old.center_x},{old.center_z})[{len(old.unique)}] -> "
              f"({new.center_x},{new.center_z})[{len(new.unique)}]; append={list(appended)}")


if __name__ == "__main__":
    main()


