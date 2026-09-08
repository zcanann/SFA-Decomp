# Cloud rendering match

Engine slot 9 (`src/dlls/engine/9/9.c`) fully matches EN v1.0 as of
2026-09-07: 15 functions, 3,088 code bytes, and 240 reported data bytes.
It is source-linked with `MatchingFor("GSAE01")`. The common GC/1.3 compiler,
optimization options, data definitions, and TU boundary are unchanged.

`renderClouds` previously matched 99.49132%, leaving the TU at 99.73446%.
The two right-hand lightning-glare vertices each evaluate Y separately, then
read the same half-size for X. Retail retains both loads. The reconstruction
now reads X through an explicit `const f32*` view while retaining the cached
Y coordinate. This adds the missing two `lfs` instructions and restores the
third vertex's Y register. All 403 instructions and the complete `.text`
section are byte-identical to the extracted retail object.

The qualifier matters to GC/1.3's frontend common-subexpression pass:

| Source | Size-symbol operands after frontend CSE | `renderClouds` |
| --- | ---: | ---: |
| Ordinary array reads | 5 | 99.49132% |
| Two explicit const-qualified X reads | 7 | 100% |

These counts include the assignment that updates the randomized size.
The initial frontend graph has seven operands in both versions. The ordinary
reads merge during `IRO_CommonSubs`, before backend register allocation.
With the two const-qualified lvalues, all seven remain through the frontend's
final stage. An otherwise equivalent scoped `const f32*` local is propagated
back to ordinary array reads and does not preserve the match. Const-qualified
value parameters and value locals do not recover the loads either.

This is a matching source-spelling reconstruction; the original spelling has
not been recovered. The view adds no volatile accesses or writes and does not
change the stored type. The earlier conclusion that only `volatile` could
produce these loads was too broad. The earlier removal of unjustified volatile
storage remains valid.

Validation:

- Only `renderClouds` changes relative to the previous source object; the other
  14 function bodies, initialized data, and named data layouts are unchanged.
- Objdiff reports all code and data at 100%. All allocated initialized section
  bytes match retail. The existing 28-byte BSS object retains its four bytes
  of linker alignment padding within the retail 32-byte span.
- Frontend and backend tracing produce the same raw object as an ordinary
  compile. The backend capture verifies 403 instructions with zero retail
  differences across 12 stages.
- `ninja all_source` and strict `ninja` pass after
  `python3 configure.py --matching`, each with a 30-second timeout. The
  source-linked DOL passes the unchanged retail checksum.

Reproduce the compiler observations with:

```sh
python3 tools/mwcc_frontend_trace.py --unit main/dlls/engine/9/9 \
  --function renderClouds --output build/flag_probe/cloud_render_frontend
python3 tools/tricky_backend_trace.py --unit main/dlls/engine/9/9 \
  --function renderClouds --output build/flag_probe/cloud_render_backend
```
