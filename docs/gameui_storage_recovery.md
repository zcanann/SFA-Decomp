# GameUI global storage recovery

`src/dlls/engine/0/0.c` previously cast a 64-byte global into a `CMenuHud`
spanning 0xC38 bytes and cast a 0xE0-byte data table into a `PauseTbl`
spanning 0x1200 bytes. Both views reached across independently defined globals.
Several texture accesses additionally assumed four-byte native pointers.

Foxhollow's native GameUI port exposed the first problem by enlarging the
64-byte backing array to `sizeof(CMenuHud)` (commit `6a3ba4b`). That is a useful
failure case, but the retail layout does not require one giant HUD object.
MWCC pools independent globals into `...bss.0` and `...data.0`; the common
assembly base register alone does not establish a source-level aggregate.

The source now accesses the existing C-menu, HUD, object and grid globals
directly. Recovered texture accesses use typed indexing. New definitions recover the
following previously anonymous or conflated storage; addresses below are EN
v1.0 anchors, with corresponding symbols updated in all five versions.

| EN address | Definition | Evidence |
| --- | --- | --- |
| `803A87F0` | Projection matrix, 0x40 bytes | `C_MTXPerspective` output |
| `803A8830` | View workspace, 0x120 bytes | Matrix output and GX matrix loads; unaccessed tail remains opaque |
| `803A8950` | Object workspace, 0x60 bytes | Matrix operations and pause-state delay reads at +0x30 |
| `803A8B48`, `803A8B98` | 40 pause icon IDs and texture pointers | Load/draw accesses and 40-entry cleanup loop |
| `803A92B8`, `803A92EC` | 13 status animation and opacity values | Independent float accesses in the status loop |
| `803A9320`, `803A9354` | 13 previous values and 13 game-bit flags | Word and byte accesses; three natural alignment bytes follow the flags |
| `803A9364` | 13 displayed status values | Status update and drawing consumers |
| `8031B030` | Four token records | Eight-byte stride, four-entry selection loop; split from the head table tail |
| `8031B560` | Five Tricky icon game bits plus terminator | Signed word loads terminating at -1 |
| `8031B764` | 45 cell/code pairs | Two halfword fields and 45-entry search; split from the button table tail |

The matrix workspace names and retained outer extents are provisional, not
claims of recovered original struct declarations. Only the first view matrix
is interpreted. The object workspace exposes eight delay slots because the
page-selection path reaches states 1 and 3 through 7; the remaining 0x10 bytes
stay opaque. No additional matrix or timer capacity is inferred from a gap.
The head table prefix and unexamined button-table bytes remain unchanged.

Declaration order preserves every existing global address. The source emits
the new definitions through ordinary compiler pooling, with no forced sections,
compiler changes, TU splits or retail-object substitution. A local pointer to
the displayed-status array preserves MWCC's health-counter register allocation.

## HUD texture array

The separate `HudTextures` overlay also mixed pointers with byte padding over
`hudTextures`. Its first text-box frame field was at the intended slot 79 on
GameCube, but at offset 464 (slot 58) with eight-byte pointers. Foxhollow changed
the padding into pointer arrays; the matching source now removes the overlay
and uses the actual `Texture*` array throughout instead.

The 102-iteration loader and its 102-entry `gHudTextureIds` list establish the
array capacity independently of the former struct. A size assertion ties that
list to `GAMEUI_HUD_TEXTURE_COUNT`. Private slot names describe draw behavior:

| Slots | Role established by consumers |
| --- | --- |
| 10–13 | Panel corner, vertical edge, fill and horizontal edge in `drawHudBox` |
| 14–16 | Mirrored task-panel corners, edges and six markers |
| 32 | Four mirrored corners around the active grid selection |
| 62 | Marker beside qualifying high-score rows |
| 68–69 | Communicator alert base and mirrored animated segments |
| 70–71 | Moving and fixed pause-menu side rails |
| 79–83 | Five frame textures handed to `gGameTextBoxFrameTextures` |
| 84 | Panel pattern used by map, head-display and pause panels |
| 92 | Four-pixel-high status-panel dividers |

These are consumer-role names, not recovered artwork filenames. Other entries
retain plain array indices until their identities are established. The old
header has no remaining consumers and is removed. No texture list entries,
array addresses or compiler settings change.

## Validation

Reports generated with `metadata.complete` removed give these complete GameUI
results. Every function and section is exact.

| Version | Functions | Code bytes | Data bytes |
| --- | ---: | ---: | ---: |
| GSAE01 | 118 / 118 | 75188 / 75188 | 9960 / 9960 |
| GSAE01_rev1 | 119 / 119 | 75304 / 75304 | 9976 / 9976 |
| GSAJ01 | 118 / 118 | 75188 / 75188 | 9960 / 9960 |
| GSAP01 | 119 / 119 | 75304 / 75304 | 9976 / 9976 |
| GSAP01_rev1 | 119 / 119 | 75304 / 75304 | 9976 / 9976 |

All five `ninja all_source` builds and strict retail DOL checksums pass.
Formatting preserves each version's raw GameUI object hash, and unrelated EN
source-object hashes are unchanged.
The unannotated whole-project reports retain only their existing TRK vector
padding/function-pairing limitation and the discarded MusyX helper exception
records described in `musyx_volume_completion.md`; neither is a new regression.

`python3 tools/test_gameui_storage.py` extracts the actual cleanup helpers and
independent global definitions, then tests ordered releases and resets with
64-bit pointers at `-O0` and `-O2` under ASan/UBSan. It preserves the retail
shutdown behavior that leaves HUD/blink pointers populated after release.
`tools/test_cmenu_set_items.py` passes, and `tools/cmenu_set_items_probe.py`
passes 10,000 cases against each of `6af408a1c1` and historical `6b1ba5bc2c`.
The probe's aggregate is only a host fixture for comparing array state; older
HUD layouts are read from the explicitly selected historical revision.

After the HUD texture overlay removal, all five complete GameUI reports and
full source/retail checksum builds retain the results above. Native checks in
`tools/test_gameui_hud_textures.py` exercise the actual panel, communicator and
text-box handoff functions at `-O0` and `-O2` under ASan/UBSan, with a distinct
pointer in every array entry. The cleanup and time-list color tests also pass.
