"""Read-only source-audit helpers: retail PPC windows and placed object locations."""
from __future__ import annotations

import argparse
import hashlib
import math
import re
import struct
from collections import Counter
from pathlib import Path

from orig.dol_tables import DolFile
from orig.romlist_audit import decompress_zlb, load_object_remap
from orig.romlist_params import load_object_defs, load_object_offsets

ROOT = Path(__file__).resolve().parents[1]
VERSIONS = ('GSAE01', 'GSAJ01', 'GSAE01_rev1', 'GSAP01', 'GSAP01_rev1')


def symbols(version):
    result = {}
    for line in (ROOT / 'config' / version / 'symbols.txt').read_text().splitlines():
        match = re.match(r'(\w+) = \.\w+:0x([0-9A-Fa-f]+);.*size:0x([0-9A-Fa-f]+)', line)
        if match:
            result[match[1]] = (int(match[2], 16), int(match[3], 16))
    return result


def disasm(args):
    from capstone import Cs, CS_ARCH_PPC, CS_MODE_32, CS_MODE_BIG_ENDIAN
    syms = symbols(args.version)
    address, size = syms[args.symbol]
    if args.offset < 0 or args.offset >= size or (args.length is not None and args.length <= 0):
        raise ValueError('Offset must be inside the symbol and length must be positive')
    start = address + args.offset
    count = min(size - args.offset, args.length or size)
    dol = DolFile(ROOT / 'orig' / args.version / 'sys' / 'main.dol')
    offset = dol.addr_to_offset(start)
    if offset is None:
        raise ValueError('Symbol is outside initialized DOL sections')
    print(f'{args.version} {args.symbol} {address:#010x} size={size:#x}')
    names = {value[0]: key for key, value in syms.items()}
    decoder = Cs(CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN)
    decoder.skipdata = True  # Gekko paired-single instructions are not decoded by Capstone.
    for insn in decoder.disasm(dol.data[offset:offset + count], start):
        annotation = ''
        if insn.mnemonic in ('bl', 'b'):
            try:
                annotation = names.get(int(insn.op_str, 16), '')
            except ValueError:
                pass
        print(f'{insn.address:08X}: {insn.mnemonic:9} {insn.op_str:30} {annotation}')


def placements(args):
    root = ROOT / 'orig' / args.version / 'files'
    definitions = {item.def_id: item for item in load_object_defs(root)}
    remap = load_object_remap(root)
    for path in sorted(root.glob('*.romlist.zlb')):
        data = decompress_zlb(path)
        offset = 0
        rows = []
        while offset < len(data):
            raw, words = struct.unpack_from('>HB', data, offset)
            size = words * 4
            if size < 0x18 or offset + size > len(data):
                raise ValueError(f'Invalid placement {path}:{offset:#x}')
            definition = definitions.get(remap.get(raw, raw))
            if definition and (definition.dll_id in args.dll or
                               (args.name and args.name.lower() in definition.name.lower())):
                record = data[offset:offset + size]
                rows.append((definition, raw, offset, record))
            offset += size
        if rows:
            if args.detail:
                for definition, raw, offset, record in rows:
                    xyz = struct.unpack_from('>3f', record, 8)
                    print(f'{path.stem} +{offset:#x} {definition.name} raw={raw:#x} dll={definition.dll_id} '
                          f'xyz={tuple(round(v, 2) for v in xyz)} bytes={record.hex()}')
            else:
                counts = Counter((r[0].dll_id, r[0].name, r[1]) for r in rows)
                print(path.stem, '; '.join(f'{name}({dll}, {raw:#x}) x{n}' for (dll, name, raw), n in counts.items()))


def neighbors(args):
    root = ROOT / 'orig' / args.version / 'files'
    definitions = {item.def_id: item for item in load_object_defs(root)}
    remap = load_object_remap(root)
    paths = [root / f'{args.map}.romlist.zlb'] if args.map else sorted(root.glob('*.romlist.zlb'))
    for path in paths:
        data = decompress_zlb(path)
        rows = []
        offset = 0
        while offset < len(data):
            raw, words = struct.unpack_from('>HB', data, offset)
            size = words * 4
            if size < 0x18 or offset + size > len(data):
                raise ValueError(f'Invalid placement {path}:{offset:#x}')
            definition = definitions.get(remap.get(raw, raw))
            xyz = struct.unpack_from('>3f', data, offset + 8)
            rows.append((offset, raw, definition, xyz, data[offset:offset + size]))
            offset += size
        for center_offset, raw, definition, xyz, record in rows:
            if definition is None:
                continue
            if definition.dll_id not in args.dll and not (args.name and args.name.lower() in definition.name.lower()):
                continue
            print(f'{path.stem} +{center_offset:#x} {definition.name} raw={raw:#x} dll={definition.dll_id} '
                  f'xyz={tuple(round(v, 2) for v in xyz)}')
            nearby = []
            for item_offset, item_raw, item_definition, item_xyz, item_record in rows:
                if item_offset == center_offset:
                    continue
                distance = math.dist(xyz, item_xyz)
                if distance <= args.radius:
                    nearby.append((distance, item_offset, item_raw, item_definition, item_xyz, item_record))
            for distance, item_offset, item_raw, item_definition, item_xyz, item_record in sorted(nearby):
                name = item_definition.name if item_definition else 'unknown'
                dll = item_definition.dll_id if item_definition else -1
                detail = f' bytes={item_record.hex()}' if args.detail else ''
                print(f'  distance={distance:.2f} +{item_offset:#x} {name} raw={item_raw:#x} dll={dll} '
                      f'xyz={tuple(round(v, 2) for v in item_xyz)}{detail}')


def hashes(args):
    for version in VERSIONS:
        path = ROOT / 'orig' / version / 'sys' / 'main.dol'
        if not path.is_file():
            print(version, 'SKIPPED (main.dol not present)')
            continue
        digest = hashlib.sha1(path.read_bytes()).hexdigest()
        config = (ROOT / 'config' / version / 'config.yml').read_text()
        expected = re.search(r'^hash:\s*[\"\']?([a-fA-F0-9]{40})', config, re.M)
        if expected is None or digest.lower() != expected[1].lower():
            raise ValueError(f'{version}: hash missing or mismatch ({digest})')
        print(version, digest, 'OK')


def sequences(args):
    root = ROOT / 'orig' / args.version / 'files'
    definitions = {item.def_id: item for item in load_object_defs(root)}
    remap = load_object_remap(root)
    offsets = load_object_offsets(root / 'OBJECTS.tab')
    objects = (root / 'OBJECTS.bin').read_bytes()
    table = (root / 'OBJSEQ.tab').read_bytes()
    casts = (root / 'OBJSEQ.bin').read_bytes()
    for raw in args.object:
        definition = definitions[remap.get(raw, raw)]
        start = offsets[definition.def_id]
        obj = objects[start:offsets[definition.def_id + 1]]
        map_offset = struct.unpack_from('>I', obj, 0x1C)[0]
        indices = range(obj[0x5E]) if args.index is None else [args.index]
        for index in indices:
            if not 0 <= index < obj[0x5E]:
                raise ValueError(f'{definition.name}: sequence index {index} out of range')
            seq_id = struct.unpack_from('>h', obj, map_offset + index * 2)[0] if map_offset else index
            first, end = struct.unpack_from('>hh', table, seq_id * 2)
            if not 0 <= first <= end or end * 8 > len(casts):
                raise ValueError(f'Invalid cast range for sequence {seq_id}')
            rows = []
            for offset in range(first * 8, end * 8, 8):
                target, flags, obj_id = struct.unpack_from('>IHH', casts, offset)
                rows.append(f'object={obj_id:#x} flags={flags:#06x} target={target:#x}')
            print(f'{definition.name} raw={raw:#x} index={index} sequence={seq_id:#x} '
                  f'cast_bytes={(end-first)*8}: ' + '; '.join(rows))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    dis = sub.add_parser('disasm')
    dis.add_argument('symbol')
    dis.add_argument('--version', choices=(*VERSIONS, 'all'), default='GSAE01')
    dis.add_argument('--offset', type=lambda v: int(v, 0), default=0)
    dis.add_argument('--length', type=lambda v: int(v, 0))
    dis.set_defaults(run=disasm)
    obj = sub.add_parser('placements')
    obj.add_argument('--version', choices=VERSIONS, default='GSAJ01')
    obj.add_argument('--dll', type=int, nargs='*', default=[])
    obj.add_argument('--name')
    obj.add_argument('--detail', action='store_true')
    obj.set_defaults(run=placements)
    near = sub.add_parser('neighbors')
    near.add_argument('--version', choices=VERSIONS, default='GSAJ01')
    near.add_argument('--map')
    near.add_argument('--dll', type=int, nargs='*', default=[])
    near.add_argument('--name')
    near.add_argument('--radius', type=float, default=100.0)
    near.add_argument('--detail', action='store_true')
    near.set_defaults(run=neighbors)
    seq = sub.add_parser('sequences')
    seq.add_argument('--version', choices=VERSIONS, default='GSAJ01')
    seq.add_argument('--object', type=lambda v: int(v, 0), nargs='+', required=True)
    seq.add_argument('--index', type=int)
    seq.set_defaults(run=sequences)
    check = sub.add_parser('hashes')
    check.set_defaults(run=hashes)
    args = parser.parse_args()
    if args.mode == 'disasm' and args.version == 'all':
        for version in VERSIONS:
            args.version = version
            args.run(args)
    else:
        args.run(args)


if __name__ == '__main__':
    main()
