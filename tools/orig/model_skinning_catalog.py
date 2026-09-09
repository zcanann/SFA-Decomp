#!/usr/bin/env python3
"""Audit serialized model skinning jobs in a version's extracted MODELS archives.

Uses the EN loader's archive/header/chunk contracts. Secondary assets are
cross-checks, not proof that missing EN files have identical contents. The
configured DOL hash is verified; archive hashes identify the inspected inputs.
"""
from pathlib import Path
import argparse
from collections import Counter
import hashlib
import json
import struct
import sys
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from version_progress import verified_dol

ROOT = Path(__file__).resolve().parents[2]


def word(data, offset):
    return struct.unpack_from('>I', data, offset)[0]


def half(data, offset):
    return struct.unpack_from('>H', data, offset)[0]


def span(data, start, size):
    if start < 0 or size < 0 or start + size > len(data):
        raise ValueError(f'Out-of-range model span: {start:#x}+{size:#x}, size {len(data):#x}')
    return data[start:start + size]


def unpack_model(record):
    span(record, 0, 0x24)
    magic, size, auxiliary, packed_size = struct.unpack_from('>4I', record)
    if magic == 0xfacefeed:
        header = span(record, auxiliary + 0x18, 16)
        if header[:4] != b'ZLB\0' or word(header, 4) != 1:
            raise ValueError('Invalid inner ZLB header')
        if word(header, 8) != size or word(header, 12) > packed_size - 16:
            raise ValueError('Outer and inner model sizes disagree')
        # The loader's outer read envelope includes padding beyond the zlib stream.
        span(record, auxiliary + 0x28, packed_size - 16)
        compressed = span(record, auxiliary + 0x28, word(header, 12))
        inflater = zlib.decompressobj()
        data = inflater.decompress(compressed) + inflater.flush()
        if not inflater.eof or inflater.unused_data or len(data) != size:
            raise ValueError('Model compressed extent/size mismatch')
        return data
    if magic == 0xe0e0e0e0:
        return span(record, auxiliary + 0x18, size)
    raise ValueError(f'Unknown model archive magic {magic:#x}')


def inspect_vertex_coordinates(data):
    """Decode base vertices, before instance scale or skinning transforms."""
    span(data, 0, 0xfc)
    flags, count, offset = half(data, 2), half(data, 0xe4), word(data, 0x28)
    fraction_bits = 0 if flags & 0x800 else 8
    raw_bounds = []
    if count:
        if offset < 0xfc:
            raise ValueError('Vertex coordinates overlap the model header')
        coordinates = list(struct.iter_unpack('>3h', span(data, offset, count * 6)))
        raw_bounds = [[min(v[axis] for v in coordinates), max(v[axis] for v in coordinates)]
                      for axis in range(3)]
    return {'flags': flags, 'count': count, 'offset': offset, 'fraction_bits': fraction_bits,
            'raw_bounds': raw_bounds,
            'local_bounds': [[v / (1 << fraction_bits) for v in bounds] for bounds in raw_bounds]}


def inspect_model(data):
    span(data, 0, 0xfc)
    result = {'normal_triplets': bool(data[0x24] & 8),
              'vertex_coordinates': inspect_vertex_coordinates(data), 'jobs': []}
    for kind, job, entry_field, base_field, stream_field in (
            ('position', 0x88, 0xa4, 0xa8, 0x28), ('normal', 0xac, 0xc8, 0xcc, 0x2c)):
        count = half(data, job + 2)
        if not count:
            continue
        entries, weights_base, stream = word(data, entry_field), word(data, base_field), word(data, stream_field)
        span(data, entries, count * 0x74)
        scale = data[job + 6] & 63
        if scale & 32:
            scale -= 64
        stride = 6 if kind == 'position' else (9 if result['normal_triplets'] else 3)
        chunks = []
        for index in range(count):
            chunk = span(data, entries + index * 0x74, 0x74)
            offset, weight_offset = word(chunk, 0x60), word(chunk, 0x64)
            vertices, skip, blocks = half(chunk, 0x70), chunk[0x72], chunk[0x73]
            weight_blocks = chunk[0x6f]
            weight_data = span(data, weights_base + weight_offset, weight_blocks * 32)
            weights = span(weight_data, 0, vertices * 2)
            stream_data = span(data, stream + offset, blocks * 32)
            records = span(stream_data, skip, vertices * stride)
            cd_indices = [i for i in range(vertices) if weights[2 * i:2 * i + 2] == b'\xcd\xcd']
            chunks.append({'count': vertices, 'matrix_indices': list(chunk[0x6c:0x6e]),
                'opaque_prefix_nonzero': any(chunk[:0x60]), 'opaque_word_nonzero': bool(word(chunk, 0x68)),
                'unknown_6e': chunk[0x6e], 'source_offset': offset, 'destination_skip': skip,
                'stream_bytes': blocks * 32, 'weight_bytes': weight_blocks * 32,
                'stream_slack': blocks * 32 - skip - vertices * stride,
                'weight_slack': weight_blocks * 32 - vertices * 2,
                'cd_weight_indices': cd_indices,
                'cd_weights_trailing': bool(cd_indices) and cd_indices == list(range(cd_indices[0], vertices)),
                'cd_weight_zero_records': sum(not any(records[i * stride:(i + 1) * stride]) for i in cd_indices),
                'weight_sums': dict(Counter(weights[i] + weights[i + 1] for i in range(0, len(weights), 2)))})
        result['jobs'].append({'kind': kind, 'scale': scale, 'stride': stride, 'chunks': chunks})
    return result


def catalog(version):
    root = ROOT / 'orig' / version
    verified_dol(root / 'sys/main.dol', ROOT / 'config' / version / 'config.yml')
    paths = sorted((root / 'files').rglob('MODELS.tab'))
    if not paths:
        raise ValueError(f'No extracted MODELS.tab files under {root / "files"}')
    models, archives, references = {}, [], []
    for path in paths:
        table, payload = path.read_bytes(), path.with_suffix('.bin').read_bytes()
        if len(table) % 4:
            raise ValueError(f'Unaligned table {path}')
        entries = [(i, word(table, i * 4)) for i in range(len(table) // 4)]
        if any(value != 0xffffffff and value >> 28 not in (0, 1, 2) for _, value in entries):
            raise ValueError(f'Unknown model table flags in {path}')
        entries = [(i, value & 0x0fffffff) for i, value in entries
                   if value != 0xffffffff and value & 0xf0000000 in (0x10000000, 0x20000000)]
        offsets = sorted({offset for _, offset in entries})
        ends = dict(zip(offsets, offsets[1:] + [len(payload)]))
        archive = str(path.relative_to(root / 'files'))
        archives.append({'path': archive, 'table_sha256': hashlib.sha256(table).hexdigest(),
                         'payload_sha256': hashlib.sha256(payload).hexdigest(), 'entries': len(entries)})
        for index, offset in entries:
            data = unpack_model(span(payload, offset, ends[offset] - offset))
            digest = hashlib.sha256(data).hexdigest()
            if digest not in models:
                models[digest] = inspect_model(data)
            if models[digest]['jobs']:
                references.append({'archive': archive, 'index': index, 'sha256': digest})
    jobs = [job for model in models.values() for job in model['jobs']]
    chunks = [chunk for job in jobs for chunk in job['chunks']]
    weight_sums = Counter()
    for chunk in chunks:
        weight_sums.update(chunk['weight_sums'])
    def extent(field):
        values = [c[field] for c in chunks]
        return [min(values), max(values)] if values else []

    summary = {'archives': len(archives), 'model_references': sum(a['entries'] for a in archives),
        'unique_models': len(models),
        'vertex_fraction_bits': dict(sorted(Counter(m['vertex_coordinates']['fraction_bits']
                                                   for m in models.values()).items())),
        'unique_model_vertices': sum(m['vertex_coordinates']['count'] for m in models.values()),
        'unique_skinned_models': sum(bool(m['jobs']) for m in models.values()),
        'skinned_references': len(references), 'jobs': len(jobs), 'chunks': len(chunks),
        'counts': dict(sorted(Counter(c['count'] for c in chunks).items())),
        'scales': dict(sorted(Counter(j['scale'] for j in jobs).items())),
        'strides': dict(sorted(Counter(j['stride'] for j in jobs).items())),
        'nonzero_prefixes': sum(c['opaque_prefix_nonzero'] for c in chunks),
        'nonzero_opaque_words': sum(c['opaque_word_nonzero'] for c in chunks),
        'unknown_6e_values': dict(sorted(Counter(c['unknown_6e'] for c in chunks).items())),
        'weight_sums': dict(sorted(weight_sums.items())),
        'cd_weight_pairs': sum(len(c['cd_weight_indices']) for c in chunks),
        'cd_weight_chunks': sum(bool(c['cd_weight_indices']) for c in chunks),
        'cd_weight_trailing_chunks': sum(c['cd_weights_trailing'] for c in chunks),
        'cd_weight_chunk_counts': dict(sorted(Counter(c['count'] for c in chunks if c['cd_weight_indices']).items())),
        'cd_weight_zero_records': sum(c['cd_weight_zero_records'] for c in chunks),
        'stream_slack_range': extent('stream_slack'),
        'weight_slack_range': extent('weight_slack')}
    return {'version': version, 'summary': summary, 'archives': archives,
            'skinned_references': references,
            'model_coordinates': {k: v['vertex_coordinates'] for k, v in models.items()},
            'models': {k: v for k, v in models.items() if v['jobs']}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('version')
    parser.add_argument('--output', type=Path, help='write complete JSON including per-chunk evidence')
    args = parser.parse_args()
    try:
        result = catalog(args.version)
    except (OSError, ValueError, struct.error, zlib.error) as error:
        parser.error(str(error))
    print(json.dumps(result['summary'], indent=2))
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
