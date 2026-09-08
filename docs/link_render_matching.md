# Link rendering match

Engine slot 60 (`src/dlls/engine/60/60.c`) matches EN v1.0 completely as of
2026-09-07: 22 functions, 5,148 code bytes, and 2,696 data bytes. The common
GC/1.3 compiler and the existing optimization profile are unchanged.

`Link_render` previously differed only in the use of `r27` and `r28`. The
draw-item pointer needs `r27`; the running X coordinate and the later text-box
alpha value need `r28`. Two source changes together recover those assignments:

- Mask the four interpolated color arguments with `& 0xff` before calling
  `gameTextSetColor`, whose arguments are promoted integers.
- Declare `opacity`, `x`, and `drawItem` in their recovered local order.

The masks preserve the unsigned-byte values of the previous casts. Controlled
compiles establish that neither change alone resolves the mismatch:

| Source | Differing instructions | Structural differences |
| --- | ---: | ---: |
| Original | 28 | 0 |
| Four color masks only | 28 | 0 |
| Local order only | 52 | 0 |
| Color masks and local order | 0 | 0 |

The GC/1.3 backend trace explains the interaction. The original graph has 181
nodes, including 13 excluded virtual nodes. The matching graph has 179 nodes
and nine excluded virtual nodes: the four color casts had produced temporary
nodes precolored to call argument registers. Their instructions disappeared,
but their interference edges still affected simplification. Removing those
nodes permits the recovered declaration order to produce the retail colors.
Both captures replay simplification without high-degree removals and verify
every physical register choice. The matching capture checks all 282 emitted
instructions, with instrumented and ordinary objects byte-identical.

The function also accepts its existing interface's unused render context,
uses native signed division by two for half opacity, and drops redundant menu
pointer casts. These cleanups preserve the matching object.

Validation includes objdiff at 100%, unchanged named-symbol layouts and
relocations relative to the previous source object, `ninja all_source`, and
the strict retail DOL checksum with slot 60 linked from source. Only the 28
register-encoding bytes change in the source object. Formatting is verified
separately against the raw object hash.

Reproduce the diagnostic capture with:

```sh
python3 tools/tricky_backend_trace.py --unit main/dlls/engine/60/60 \
  --function Link_render --graph \
  --output build/flag_probe/link_render_matching_backend
```
