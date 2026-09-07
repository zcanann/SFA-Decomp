# Effect3 matching

`src/dlls/engine/28/28.c` matches EN v1.0 (`GSAE01`) completely as of
2026-09-07: five functions, 7,812 code bytes, and 356 data bytes. The existing
GC/1.3 compiler and optimization profile are unchanged.

## Source correction

The four rectangle-edge effect cases make sixteen calls whose bounds come from
floating-point spawn parameters. Each bound is converted directly to `s16`:

```c
cfg.startPosZ = randomGetRange((s16)-spawnParams->posZ, (s16)spawnParams->posZ);
```

The previous `(s16)(s32)` conversion produced the same emitted conversion
instructions but a different register graph. The function also uses its
`spawnParams` parameter directly instead of copying `spawnParamsIn` into a local.
Both changes are needed. Controlled compiles against the original source gave:

| Source | Differing instructions | Structural differences |
| --- | ---: | ---: |
| Original double casts and parameter alias | 14 | 0 |
| Remove only the parameter alias | 95 | 0 |
| Use only direct `s16` casts | 89 | 0 |
| Direct casts and direct parameter use | 0 | 0 |

The explicit `hasAttachedSource` local is also unnecessary. Testing the spawn
flag at both consumers lets CSE retain the retail mask value in `r31` and is
byte-identical to keeping the local after the two corrections above.

## Compiler evidence

`tools/tricky_backend_trace.py` captured the ordinary GC/1.3 compiler under
LLDB. Its instrumented output was required to equal the ordinary raw object.
The baseline graph contained 778 nodes, including 32 excluded virtual nodes
precolored to the call argument registers `r3` and `r4`. Each two-step bound
conversion initially emitted an `extsh` into a temporary followed by a move to
its argument register. The copies disappeared, but the excluded nodes still
contributed edges to the graph's degree counters.

After ordinary low-degree simplification, `effectId`, `spawnFlags`, and the
attachment mask each retained degree 46, above the 29 available GPRs. Weighted
high-degree removals selected the mask, flags, then effect ID. Coloring in the
reverse order put those values in `r29`, `r30`, and `r31`, respectively.

The corrected graph has 745 nodes and no excluded virtual nodes. It needs no
high-degree removal. Its argument homes are the retail `r26` through `r30`,
with the mask in `r31`. The trace validates all 1,949 emitted instructions over
15 captured stages and replays 713 physical register choices with zero retail
differences. The decoder now recognizes and checks the signed division used by
the color calculations (`divw`, backend opcode `0x45`).

This supersedes the old claim that the parameter homes were unreachable from
source changes. An unchanged final instruction shape does not imply an unchanged
allocator graph; single-edit regressions can conceal a correct combined repair.

## Verification

- Objdiff: all five functions and the complete unit at 100%.
- Raw function bytes, initialized section bytes, section sizes and alignments,
  and all shared named symbol offsets match the retail object. MWCC's `.sdata2`
  writable ELF flag differs from the extracted reference; the linked bytes match.
- `python3 configure.py --matching`, bounded `ninja all_source`, and bounded
  strict `ninja` pass with this unit linked from source (`main.dol: OK`).
- Backend decoder/graph/trace tests pass, including division opcode, operand,
  and encoding rejection checks.

Reproduce the diagnostic capture with:

```sh
python3 tools/tricky_backend_trace.py --unit main/dlls/engine/28/28 \
  --function Effect3_spawnObject --graph \
  --output build/flag_probe/effect3_backend
```
