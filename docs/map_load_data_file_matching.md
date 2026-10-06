# `mapLoadDataFile` matching

`main/pi_dolphin.c` is 100% code and data (57/57 functions) as of 2026-09-26 and links as
`MatchingFor("GSAE01")`.

## The residual was a declaration, not register allocation

For months `mapLoadDataFile` sat at 99.71% with an identical instruction stream and a
colouring-only residual. The slot accessors went through named "biased" locals
(`slotPtrAddr = (slot << 2) + ((u32)&tbl->ptrs[0] + 0x6A28)`, dereferenced at `- 0x6A28`).
That spelling reproduced retail's `addis`/`add` web with the low offset folded into each load,
but it made the web a declared object. Retail's web is a compiler temp, so the colouring differed.

The biased locals existed because plain `tbl->ptrs[slot]` made the GC/1.3 IR share the whole
address as one temp, adding an `addi` that retail doesn't have. Standalone probes pin the
trigger down to one declaration:

| Base object | Repeated `t->ptrs[slot]` |
| --- | --- |
| `extern u8 gA[];` cast to the struct type (unsized) | full address shared, `addi` + `lwz 0(r)` |
| `extern u8 gB[0x160];` (sized), with or without `&` | folded, `lwz -27176(r)` (retail) |
| any struct-typed object, `extern` or defined | folded (retail) |

`gResourceFileTable` was declared `extern u8 gResourceFileTable[];`. Giving it its size
(`[0x160]`, matching its definition) lets every accessor use the plain typed form. The
index-first spellings `((s) << 2) + (u32)tbl->ids` (and `<< 1` for owners, `slot << 2` for
ptrs) reproduce retail's `slwi` before `addis` order.

## Linking the unit

Promoting the unit exposed a latent link problem. `.sbss` padding `sPiUnused1` was `static`,
so FORCEACTIVE couldn't keep it and the linker stripped it, shifting every later `r13`
offset by 4. It is now global and listed under `force_active` in `config/GSAE01/config.yml`,
like `sPiUnused0/2/3`.

## Method

The instruction stream matched long before the registers did. Captures from
`tools/tricky_backend_trace.py`, retail-register projection, a replay of the colourer and an
LLDB hook on the IR range splitter showed which objects needed different numbering. Probes
then showed the numbering came from the IR sharing decision above.

## MAPS table and page loading (2026-10-06)

`gMapsTab` now points to `MapRomListOffsets`, the seven signed byte offsets in
each MAPS.tab record. It previously stored the result of a pointer-writing loader
in an `int`, which cannot hold a native pointer. `mapGetRomListAndOffsets` and
`mapInitSetRects` now relocate sections relative to byte pointers without
truncating their allocation addresses. Both use the canonical `MapRomListPage`;
the latter's duplicate partial header has been removed.

The retail record contract is:

| MAPS.tab word | MAPS.bin section |
| --- | --- |
| 0 | 0x38-byte page header |
| 1 | Four-byte cells, `sizeX * sizeZ` entries |
| 2, 3 | Two cell-rectangle sections, each eight bytes per cell |
| 4, 5 | Two equally sized layer-rectangle sections |
| 6 | Packed object data |
| Following word | End of this page; normally the next record's header offset |

The final page uses a boundary word in the table footer. The EN corpus has 115
populated pages and two object-only entries (104 and 114): those two records
have seven equal offsets and own a 32-byte FACEFEED block, with no page header.

`mapsBinGetRomlistSize` reads signed halfwords from the **MAPS.bin page header**
at +0x1C and +0x1E, then obtains `PackHeader.decompressedSize` at the objects
offset. The first halfword is the object count used to size the loaded-object
bitmap. The second remains `unk1E`: it is not consistently the layer-rectangle
count. Map 12 stores 5 there but has 64 bytes in each layer-rectangle section.
Missing resident MAPS.bin or MAPS.tab buffers still leave all outputs untouched.

The allocation reserves the complete stored page, decompressed object bytes,
`ceil(objectCount / 8)` bitmap bytes, and another 0x401 bytes. The bitmap starts
after the page and decompressed-byte reserve; clearing includes one extra byte.
The section offset macros retain the retail multiply-by-seven/shift-by-two
indexing and MWCC addressing modes using pointer-width arithmetic. Direct typed
array indexing changed code generation. Global declaration order and the generic
`gCurRomListPage` storage shape remain unchanged.

Foxhollow's `game/src/main/shader.c` at
`894de8a8edecfad2e455f1a6345e328f50c74aba` independently shows the native pointer
problem, plus the separate header allocation and endian decoding a complete
native loader needs. Dinosaur Planet's `src/map.c` at
`c4340802dc9f62e1181d00cc34c3175fca6ca4be` has the corresponding seven-word table,
page relocation, object bitmap and bounds setup. Its section order and allocation
contract differ; they were not copied into SFA.

`tools/test_map_page_loading.py` exercises the production metadata reader,
relocator and bounds helper in 5,760 scenarios at both `-O0` and `-O2` with ASan
and UBSan. It checks the complete allocation and guards, all six pointers,
bitmap contents, callback ordering, skipped indexing, missing resident buffers,
and bounds output with addresses above 4 GiB. A separate test checks the retail
table and section sizes. Native fixtures contain decoded host-layout headers;
these tests do not claim raw retail headers can be loaded directly on a host.
Six deliberate faults were rejected, including truncating either pointer base,
using the wrong section, omitting the bitmap's extra byte, restoring a raw
metadata field offset, and ignoring the index-control argument. The existing
resource-buffer registry harness also passes with the canonical page layout.

Both complete TUs (`shader`: 145 functions; `pi_dolphin`: 57) match 100% code and
data in all five configured versions. `all_source` and the strict retail DOL
checksum pass for each version, with no retail object substitution. Full objdiff
inventories retain only the existing TRK vector-carving and MusyX discarded-data
report exceptions. The pi_dolphin object remains byte-identical; shader changes
only anonymous literal symbol numbering, with unchanged section contents, named
symbol offsets and normalized relocations. Formatting is verified separately
against the recovered objects.
