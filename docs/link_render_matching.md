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

## Shared records and regional font lookup (2026-09-09)

Link now uses the same `TitleMenuTextEntry` as its title-menu, save-select and
warpstone callers. `Link_setup` copies complete 0x3C-byte records and replaces
the template asset ID at +0x10 with a loaded texture pointer. The canonical
record therefore exposes both through a union. The duplicate local
`LinkMenuItem` and 25-slot count are removed, and layout assertions live beside
the shared definition. Caller template bytes and every other source object
remain unchanged in all five versions.

The two remaining regional mismatches were the text-only fallback in
`Link_refreshOverlappingItemTimers` and `Link_scanItemVerticalBounds`.
EN v1.0 and JP select font 0 for Japanese and font 4 otherwise. EN rev1 and both
PAL revisions instead read `sLanguageNameTable[getCurLanguage()].fontId` before
loading the line height. A private expression macro shares this selection at
all three sites and preserves the extra two pixels and existing comparisons.
The six retail font IDs are `[4, 4, 4, 4, 0, 4]` in every version; the source
retains each binary's lookup policy rather than assuming equivalence for
out-of-range language IDs or modified table contents.

PAL's getter was still named `fn_80019DAC`. All three direct calls in each PAL
DOL resolve to `80019DAC`; its two instructions load the current-language word
through r13 and return. The independently read r13 bases resolve that load to
`803DE1E4` in PAL v1.0 and `803DE3A4` in PAL rev1, the respective `curLanguage`
locations. Both configs now call it `getCurLanguage`, matching its source API.
The same call/load audit passes in EN, EN rev1 and JP. All input DOLs pass their
configured SHA-1 before these reads.

Both regional functions are now exact, completing the Link unit in EN rev1 and
both PAL revisions. All 22 functions and 2,696 data bytes match in all five
versions: text is 5,148 bytes in EN/JP and 5,196 in the other versions. The
non-code sections, alignment and global data-symbol layouts are unchanged.
EN/JP preserve every instruction and relocation; removing the private record
only renumbers one anonymous constant label from `@289` to `@288`.

Every version passes `all_source`, the all-retail control link, the Link-only
source substitution link and the native strict checksum target. The complete
source-object census finds changes only in Link, including for all consumers
of the expanded shared header. Compiler profiles, source boundaries and
expected checksums are unchanged.
