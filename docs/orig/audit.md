# `orig/` audit notes

This is a side-agent reconnaissance pass over the bundled retail assets in `orig/`, focused on data that can accelerate recovery work without touching `src/`.

## Tools

- `python tools/orig/orig_audit.py`
  - Inventories `orig/GSAE01`, compares EN/PAL/JP control-data files, reports duplicate content, and extracts a few useful `main.dol` strings.
  - Cross-region comparison intentionally skips bulky media files: `.adp`, `.iso`, `.sam`, `.thp`.
- `python tools/orig/romlist_audit.py`
  - Decompresses `*.romlist.zlb`, resolves object IDs through `OBJINDEX.bin`, mines stable record sizes, and reports high-usage object definitions plus minimal romlists.
- `python tools/orig/map_catalog.py`
  - Recovers the EN map catalog directly from `MAPINFO.bin`, `MAPS.*`, `globalma.bin`, `TRKBLK.tab`, and `orig/GSAE01/sys/main.dol`.
  - Emits either a markdown summary or a CSV dump of all 117 map IDs, including romlist aliases and dir-backed vs root-only map families.
- `python tools/orig/dol_tables.py`
  - Recovers the EN runtime file-ID table and `.ctors` / `.dtors` directly from `orig/GSAE01/sys/main.dol`.
  - Cross-checks runtime aliases against the retail EN FST so alias-only loader names stand out immediately.
- `python tools/orig/dol_xrefs.py`
  - Recovers direct string xrefs from the EN retail DOL so source-tagged warnings and file-path strings can be tied back to concrete code addresses.
  - Resolves those xrefs through `config/GSAE01/symbols.txt` so current `fn_...` ranges can be opened immediately.
- `python tools/orig/dol_vtables.py --stores-only`
  - Scans the EN retail DOL for short function-pointer tables and keeps the ones that are written into object-like registers by code.
  - Gives constructor-style anchors for vtable or callback-table recovery without guessing from decomp artifacts.

Focused notes for that tool live in [map_catalog.md](/C:/Projects/SFA-Decomp/docs/orig/map_catalog.md).
Focused notes for the DOL runtime tables live in [dol_tables.md](/C:/Projects/SFA-Decomp/docs/orig/dol_tables.md).
Focused notes for direct DOL string xrefs live in [dol_xrefs.md](/C:/Projects/SFA-Decomp/docs/orig/dol_xrefs.md).
Focused notes for constructor-backed function-pointer tables live in [dol_vtables.md](/C:/Projects/SFA-Decomp/docs/orig/dol_vtables.md).

## High-value findings

### 1. Disc-root map assets are an exact duplicate of `darkicemines/`

The root copies of the usual map payloads are byte-identical to `orig/GSAE01/files/darkicemines/`:

- `ANIM.BIN`
- `ANIM.TAB`
- `ANIMCURV.bin`
- `ANIMCURV.tab`
- `mod27.zlb.bin`
- `MODELIND.bin`
- `MODELS.bin`
- `MODELS.tab`
- `OBJSEQ.bin`
- `OBJSEQ.tab`
- `OBJSEQ2C.tab`
- `TEX0.bin`
- `TEX0.tab`
- `TEX1.bin`
- `TEX1.tab`
- `VOXMAP.bin`
- `VOXMAP.tab`

That strongly suggests the apparent "global" root bundle is not a separate format family. It looks more like one concrete main-map payload that the loader can treat as the root/default set. This is useful when naming file loaders, reconstructing file ID tables, and deciding how `files/` root assets relate to `mapname/` assets.

### 2. Tiny romlists are minimal object-format test cases, not empty stubs

`romlist_audit.py` finds:

- 124 root `*.romlist.zlb` files
- 56 single-record romlists
- 55 of those 56 contain exactly one `0x000D` object (`TrickyFood`)
- the remaining one is `frontend2.romlist.zlb`, containing one `0x001E` object (`BGSweapon`)

Most of these single-record romlists decompress to exactly `0x20` bytes. That makes them ideal for recovering the base romlist object header:

- `s16 object_id`
- `u8 size_words`
- `u8 flags`
- fixed transform / map / id fields
- optional params beginning at `+0x18`

If someone wants to confirm the loader and spawn path for one record end-to-end, these files are the cheapest possible targets.

### 3. `MAPINFO.bin` and `WARPTAB.bin` are already clean, fixed-structure data

The EN audit confirms:

- `MAPINFO.bin` is 117 records of `0x20` bytes each
  - layout matches `>28s 2b h`
  - examples: `Ship Battle`, `Dragon Rock - Top`, `ThornTail Hollow`
  - map type histogram: `0=66`, `1=42`, `3=1`, `4=8`
- `WARPTAB.bin` is 128 records of `0x10` bytes each
  - layout matches `>3f 2h`
  - layer histogram: `-2=4`, `-1=7`, `0=110`, `1=1`, `2=6`

These are straightforward candidates for early real struct definitions instead of anonymous blobs.

### 4. Several control files are region-stable and can be analyzed once

Byte-identical across `GSAE01`, `GSAP01`, and `GSAJ01`:

- `files/BITTABLE.bin`
- `files/OBJECTS.bin2`
- `files/OBJINDEX.bin`
- `files/MAPINFO.bin`
- `files/MAPS.tab`
- `files/WARPTAB.bin`
- `files/TABLES.bin`
- `files/TABLES.tab`
- `files/TRKBLK.tab`
- `files/WEAPONDA.bin`
- `files/globalma.bin`

These are good places to spend reverse-engineering time because any recovered structure is very likely portable across all three regions.

### 5. Several other globals are same-size or near-size across regions, but content differs

Good candidates for "same parser, different content" analysis:

- `files/ANIM.TAB`
- `files/ANIMCURV.tab`
- `files/FONTS.bin`
- `files/HITS.bin`
- `files/HITS.tab`
- `files/MAPS.bin`
- `files/TEXPRE.bin`
- `files/TEXPRE.tab`
- `sys/main.dol`

For example:

- `MAPS.tab` is identical across all three regions, but `MAPS.bin` differs in all three.
- `HITS.tab` differs only in PAL; EN and JP match.
- `OBJECTS.bin` matches between EN and PAL, while JP differs.

That split is likely useful when separating loader logic from per-region content.

### 6. `main.dol` still leaks useful internal file-family names

`orig_audit.py` extracts file-table-like strings directly from `orig/GSAE01/sys/main.dol`. The useful part is not the literal disc filenames we already know; it is the internal aliases that do **not** match the extracted tree one-to-one:

- `BLOCKS.bin`
- `BLOCKS.tab`
- `DLLSIMPO.bin`
- `CACHEFON.bin`
- `PREANIM.bin`
- `PREANIM.tab`

This is useful evidence for loader naming and for understanding why `modXX.zlb.bin` / `modXX.tab` behave like the runtime "BLOCKS" family.

The same pass also surfaces a few source-file-like strings still embedded in the DOL:

- `expgfx.c`
- `objHitReact.c`
- `curves.c`
- `camcontrol.c`
- `n_attractmode.c`
- `SHthorntail.c`
- `dvdfs.c`

That is not enough for a full source map, but it is enough to seed file/subsystem naming around nearby functions or warning strings.

### 7. The EN retail DOL gives a real runtime file-ID table and live init tables

`dol_tables.py` recovers an 88-entry runtime file-ID table at `0x802CBECC` covering IDs `0x00` through `0x57`.

This gives direct EN loader anchors such as:

- `0x25` `BLOCKS.bin`
- `0x26` `BLOCKS.tab`
- `0x42` `DLLS.bin`
- `0x43` `DLLS.tab`
- `0x44` `DLLSIMPO.bin`
- `0x51` `PREANIM.bin`
- `0x52` `PREANIM.tab`

It also proves that the later IDs are not just random duplicates; they are a second runtime ID range that intentionally reuses map-family names like `MODELS`, `BLOCKS`, `ANIM`, `TEX0`, `TEX1`, `VOXMAP`, and `ANIMCURV`.

On the split side, the same tool confirms the live EN init tables:

- `.ctors[0]` -> `__init_cpp_exceptions`
- `.ctors[1]` -> `fn_802952E8`
- `.dtors[0]` -> `__destroy_global_chain`
- `.dtors[1]` -> `__fini_cpp_exceptions`
- `.dtors[2]` -> `__destroy_global_chain`

That gives one concrete unnamed constructor target in the retail binary and removes guesswork around the EN `.ctors` / `.dtors` contents.

### 8. The EN retail DOL still ties several anonymous functions back to source-tagged strings

`dol_xrefs.py` finds direct text xrefs from current anonymous function ranges to strings such as:

- `objHitReact.c: sphere overflow! %d` -> `fn_8003549C+0x140`
- `curves.c: MAX_ROMCURVES exceeded!!` -> `fn_800E556C+0x18`
- `<camcontrol.c>  failed to load triggered camaction actionno %d` -> `fn_80102D3C+0x288`
- `SHthorntail.c` -> `fn_801D5764+0x364`
- `%s.romlist.zlb` -> `fn_800484A4+0x40`, `fn_800484A4+0xDC`

This is useful because it converts leftover retail strings into directly actionable EN code anchors for naming, split proposals, and subsystem clustering.

### 9. The EN retail DOL still exposes at least one real constructor-backed vtable-like table

`dol_vtables.py --stores-only` keeps the candidate set deliberately small and already finds two object-owned table writes in the EN retail DOL:

- `0x8031ABF4`
  - short 4-slot function-pointer table
  - loaded from `fn_80136CE4+0x70`
  - stored to `r30+0x0`
  - strongest current vtable-like hit
- `0x8031E614`
  - 9-slot function-pointer table
  - loaded from `fn_80140340+0x30`
  - stored to `r30+0x730`
  - more likely a callback/state table than a primary vtable

The first one is the main takeaway: it gives one concrete retail data address and one constructor-like function that can be attacked together while recovering class boundaries or virtual methods.

## Romlist mining highlights

`romlist_audit.py` reports:

- 814 canonical object IDs referenced by root romlists
- only one object with varying romlist record size: `0x0491 curve`
  - sizes seen: `13w`, `14w`, `15w`, `17w`
- busiest romlists:
  - `snowmines.romlist.zlb`: 1276 placements
  - `wallcity.romlist.zlb`: 1271 placements
  - `wastes.romlist.zlb`: 1188 placements
  - `capeclaw.romlist.zlb`: 1172 placements
  - `hollow.romlist.zlb`: 1100 placements

High-usage definitions worth prioritizing for struct recovery because they give lots of examples:

- `0x0491 curve`
- `0x04C4 TrickyWarp`
- `0x051C TrigPln`
- `0x059C CmbSrc`
- `0x04F9 LargeCrate`
- `0x04BC HitAnimator`
- `0x0493 setuppoint`

`curve` is especially valuable because the data clearly varies in length while still representing one canonical object type.

## Reference leverage inside `reference_projects/rena-tools`

The local reference tree already contains useful SFA-specific notes and scripts that align with this audit:

- [reference_projects/rena-tools/StarFoxAdventures/misc-scripts/getobjparamlengths.py](/C:/Projects/SFA-Decomp/reference_projects/rena-tools/StarFoxAdventures/misc-scripts/getobjparamlengths.py)
- [reference_projects/rena-tools/StarFoxAdventures/misc-scripts/parseglobalma.py](/C:/Projects/SFA-Decomp/reference_projects/rena-tools/StarFoxAdventures/misc-scripts/parseglobalma.py)
- [reference_projects/rena-tools/StarFoxAdventures/notes/files.md](/C:/Projects/SFA-Decomp/reference_projects/rena-tools/StarFoxAdventures/notes/files.md)
- [reference_projects/rena-tools/StarFoxAdventures/notes/maps.md](/C:/Projects/SFA-Decomp/reference_projects/rena-tools/StarFoxAdventures/notes/maps.md)
- [reference_projects/rena-tools/StarFoxAdventures/notes/hits.txt](/C:/Projects/SFA-Decomp/reference_projects/rena-tools/StarFoxAdventures/notes/hits.txt)

The new local tools are meant to keep the most immediately useful parts reproducible inside this repo, without depending on the structure of the reference project.

## Suggested follow-up targets

- Turn `MAPINFO.bin` and `WARPTAB.bin` into real struct definitions and small dumpers under the main repo tooling.
- Use the tiny `TrickyFood` romlists to confirm the base placement-record layout in code.
- Use `curve` as the first variable-length object to recover a principled parameter decoder.
- Follow the `BLOCKS.bin` / `BLOCKS.tab` DOL strings into loader code and rename the `modXX` path family accordingly.
- Use `python tools/orig/dol_tables.py --search BLOCKS DLLS PREANIM` while naming file-loader switch tables and split candidates around the EN DOL loaders.
- Use `python tools/orig/dol_xrefs.py --search camcontrol curves SHthorntail romlist` before naming anonymous functions that already have retail string evidence.
- Use `python tools/orig/dol_vtables.py --stores-only` before recovering a class-like subsystem that seems to write a function pointer to offset `0`.
- Decide whether the `darkicemines` root duplication should drive a first-pass file-ID enum or loader switch table.
