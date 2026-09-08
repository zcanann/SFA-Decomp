# Model vertex coordinate encoding

`MODEL_FLAG_INTEGER_VERTEX_COORDS` names bit `0x800` of the halfword at
`ModelFileHeader + 0x02`. Set means integer signed-halfword XYZ coordinates;
clear means signed-halfword XYZ with eight fractional bits. Each record is
six bytes, selected through the vertex pointer at `+0x28`, with the count at
`+0xE4`.

Two independent EN consumers establish the interpretation:

- `Model_GetVertexPosition` (`80026E00`) directly converts the three halfwords
  when the bit is set and divides by `256.0f` otherwise.
- `trackBuildModelTriangles` (`80067B84`) additionally applies the instance's
  scale. Its set-bit branch multiplies by that scale; the clear-bit branch
  multiplies and then divides by `256.0f`.

Both readers use the canonical flag from `include/main/model.h`. Their
arithmetic order, pointer storage, and existing signed accesses remain intact.
Unrelated object/instance flags, model-resource scratch offsets, and joint
matrix instruction constants with the same numeric value are distinct.

## Serialized evidence

The model catalog now audits base vertex spans and exposes `model_coordinates`
for every unique decompressed model, including models without skinning jobs.
Each SHA-256 key records the header flags, count, offset, fractional-bit count,
raw signed bounds, and decoded local bounds. Bounds precede instance scaling
and skinning transforms; they are not final world or animated bounds.

The available EN rev1 and JP extractions each contain:

| Encoding | Unique models | Vertices |
| --- | ---: | ---: |
| Integer (`0x800` set) | 43 | 2,840 |
| Eight fractional bits (`0x800` clear) | 784 | 177,353 |
| Total | 827 | 180,193 |

All declared base vertex spans fit outside the fixed header and inside their
own decompressed model. All 51 skinned models use eight fractional bits, and
their position job's quantization scale is independently eight. This agrees
with the GQR7 skinning contract; the flag is not substituted for the job's scale.

The two regions share 826 identical decompressed model payloads. Their one
region-specific payload apiece has the same flags, count, vertex offset, and
coordinate bounds; equal bounds do not establish full asset equality. The
51 skinned payloads remain byte-identical across the regions. EN's extracted
asset directory is empty, so these counts do not describe missing EN assets.

```
python3 tools/orig/model_skinning_catalog.py GSAE01_rev1 --output /tmp/vertices-rev1.json
python3 tools/orig/model_skinning_catalog.py GSAJ01 --output /tmp/vertices-jp.json
python3 -m unittest discover -s tools -p test_model_skinning_catalog.py
```

The eight tests cover archive envelopes and skinning records plus signed
coordinate extrema in both encodings, truncated/header-overlapping/out-of-range
vertex spans, and an empty stream whose unused pointer must not be dereferenced.
Each real asset run verifies its configured DOL hash and records archive hashes.

All 1,004 EN source objects and 988 objects in each verified secondary version
remain byte-identical, and complete objdiff reports are unchanged. All four
`all_source` builds and the strict EN retail checksum pass. The shared macro
retains the unsuffixed integer type of the original mask. Formatting is verified
separately; no matching-status or compiler changes are needed.
