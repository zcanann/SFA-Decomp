# Asset-loader boundary and game-loop reset match

`checkReset` now matches all 828 retail EN bytes using ordinary diagnostic
string literals. The leading asset-loader input is separate from `gameloop.c`;
the main-loop and button-object code remain together. This corrects data and
BSS ownership, not optimization profiles. Both inputs retain GC/1.3 and the
existing `-opt nopeephole,noschedule -inline noauto` settings.

## Independent boundary evidence

Retail `checkReset` loads its shared diagnostic base at `802CA460`, the first
byte of the version/reset metadata. Its six message offsets are `D0`, `EC`,
`104`, `118`, `12C`, and `13C`. The preceding 32 bytes at `802CA440` form the
asset dispatcher's eight-entry jump table.

With ordinary string literals in the merged source, an LLDB capture of GC/1.3
shows that the first jump table anchors `...data.0` at section offset zero.
All six diagnostic literals resolve to that pool; their offsets are 32 bytes
larger than retail. The compiler does not silently restart pooling at the
version/reset metadata. The traced object is byte-identical to an ordinary
compile. The earlier explicit diagnostic pointer hid this ownership problem.

A separate retail BSS clue agrees: the loader's private request occupies
`8033BF88..8033BFB4`, while the player-trail buffer starts at `8033BFB8`.
The same four-byte gap follows the 44-byte request in all five versions.
A separate input naturally supplies the eight-byte linker alignment; no
padding field, dummy object, alignment override, or section directive is needed.

The text cluster is contiguous: the dispatcher, two empty lifecycle hooks,
and four request builders occupy `8001F54C..8001F7AC`. The dispatcher is private
and is called only by those builders. The request is likewise private to that
cluster. `crash` begins the following game-loop input at `8001F7AC`.
`asset_load.c` is a descriptive reconstructed name, supported by the existing
API header; it is not claimed as an original filename. `source_leaks.py` and
`source_matrix.py` found no `gameloop`, `assetload`, or `main.c` source-tag clue.

| EN input | Text | Data | BSS |
| --- | --- | --- | --- |
| `main/asset_load.c` | `8001F54C..8001F7AC` | `802CA440..802CA460` | `8033BF88..8033BFB4` |
| `main/gameloop.c` | `8001F7AC..80021370` | `802CA460..802CA5F0` | `8033BFB8..8033C7A0` |

The gap remains unclaimed. Small-data ownership stays with `gameloop.c`.
Every function remains in retail order. This boundary is earlier than the
optimization-driven button-object/main-loop cuts removed in the prior audit;
those cuts are not restored.

## Diagnostic storage

The seven `OSReport` calls now contain their actual string literals. MWCC emits
the same bytes and alignment in `.data`, including the warning used by
`mainSetBits`, and creates the shared address base for `checkReset` itself.
The manual 204-byte backing block, typed offset overlay, and hoisted pointer
are removed. The version metadata and finished-init message remain as before.

Reproduce the compiler observation on the final source with:

```sh
python3 tools/mwcc_data_pool_trace.py --unit main/main/gameloop \
    --function checkReset --output build/gameloop_pool_trace
python3 tools/verify_source_link.py GSAE01 main/asset_load.c main/gameloop.c
```

The trace tool now accepts a function filter and retains `gameTextGet` as its
default. The final trace anchors the data pool at `sGameLoopResetMessages`.

## Regional verification

All five input DOLs pass their configured SHA-1 before comparison. The regional
projection was run with `--write` and reviewed: it independently reproduces both
new boundaries in every version. Its unrelated symbol proposals were discarded.
In PAL it omits the previously verified eight-byte unsigned-to-float bias at
the start of `.sdata2`; that existing ownership is retained.

- EN, EN rev1 and JP: all 34 game-loop functions and all seven asset-loader
  functions are exact. Independent all-retail and two-source-substitution links
  reproduce each entire retail DOL. Both units are enabled for matching links.
- Both PAL releases: `checkReset` becomes exact, bringing the game-loop input
  to 33/34 exact functions. `askProgressiveScanMode` retains its existing
  99.380165% match; the game-loop input stays NonMatching. The seven-function
  asset-loader input passes an independent source link and is enabled in each
  progress manifest.
- All five versions pass `ninja all_source` and the native strict retail
  checksum target. No checksum, compiler profile, or linker setting changes.

The new EN function match adds 828 matched code bytes. Completing the existing
source ownership additionally enables both inputs in the matching link; this
is not a claim that their already-exact functions were newly decompiled.
