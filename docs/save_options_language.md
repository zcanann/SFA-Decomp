# Save options and language recovery

The save-settings unit (`dlls/engine/21/21.c`) and save-game unit
(`dlls/engine/23/23.c`) now match every function and all data in all five
retail versions. PAL v1.0 and PAL rev1 share the newly recovered options flow.

## Retail behavior

PAL moves the defaults previously spelled out in `SaveGame_initialise` and
`loadGameOptions` into `saveFileStruct_resetOptions`. It clears the complete
`0xE4`-byte `SaveData`, enables subtitles and rumble, marks options valid, and
sets the three volumes to 127. It then reads the console language through
`OSGetLanguage`:

| Console language | Saved language index | Gametext language ID |
| --- | --- | --- |
| English, Dutch, or other/default | 0 | 0 (English) |
| French | 1 | 1 |
| Italian | 2 | 3 |
| Spanish | 3 | 5 |
| German | 4 | 2 |

`loadSaveSettings` applies the existing display, audio, UI, and camera settings,
then translates the saved index through `gSaveGameLanguageMap` and calls
`gameTextSetLanguage`. The latter retail function stores the current language,
updates the localized text/font selection, and reloads text directories. This
change identifies its API; its source body remains a gametext recovery task.

`saveGameOptions` passes the options record to `cardWriteOptions`. That wrapper
uses the existing loading-message and retry loop, dispatching
`saveGameWriteOptionsCb` with the options pointer as its fourth callback argument.
The callback copies only the `0xE4`-byte options trailer at card-buffer offset
`0x1F14`, attempts `saveGame_doWrite(2)`, and falls back to mode 1 on zero.
It does not copy a game slot. Both card functions are now reconstructed source.

The initializer's twenty explicit transient-map stores are replaced with one
loop over `SAVEGAME_TRANSIENT_MAP_BIT_COUNT`. The same loop matches every
version: MWCC emits the PAL pointer advances after the reset-helper call while
retaining the original EN/JP instruction sequence with inline defaults.

## Symbols and ownership

| Symbol | PAL v1.0 | PAL rev1 |
| --- | --- | --- |
| `saveFileStruct_resetOptions` | `800E82A4` | `800E829C` |
| `SaveGame_func08_nop` | `800EA490` | `800EA488` |
| `SaveGame_release` | `800EA494` | `800EA48C` |
| `SaveGame_initialise` | `800EA4C0` | `800EA4B8` |
| `gSaveGameLanguageMap` | `803DD084` | `803DD244` |
| `gameTextSetLanguage` | `80019C30` | `80019C30` |
| `cardWriteOptions` | `8007DD08` | `8007DD08` |
| `saveGameWriteOptionsCb` | `8007EA2C` | `8007EA2C` |

The three save-game callbacks were unnamed in the PAL configs despite having
existing source definitions. Their names now follow the verified bodies and
callback table. The five-byte language table remains in engine/23's established
`.sdata` window, between the current-slot byte and `"FOX"`. Its bytes are
`00 01 03 05 02`; ordinary compiler alignment reproduces both surrounding gaps.
The old eleven-byte symbol spanning padding and the table was removed.

An independent PAL rev1 source link also exposed an existing name collision:
engine/21's source constant `lbl_803E06C4` collided with a different retail
constant in `track_dolphin`. The engine/21 zero now has the unit-owned name
`gCurvesUnusedZero` in every version. Its verified addresses are `803E06C4`
(EN), `803E1344` (EN rev1), `803E07E4` (JP), `803E1ECC` (PAL), and `803E208C`
(PAL rev1). Other units' address-based symbols are preserved.

## Validation

For each PAL version:

| Unit | Exact functions before → after | Exact code after | Exact data after |
| --- | --- | --- | --- |
| engine/21 | 30 → 32 | 11,712 bytes | 1,008 bytes |
| engine/23 | 50 → 55 | 8,240 bytes | 5,532 bytes |
| intersect_memcard | 17 → 19 | 3,664 / 4,808 bytes | 48 / 208 bytes |

That is 18 newly exact function instances across the two PAL versions and four
new completed-unit manifest entries. The memory-card unit stays incomplete:
`showMemCardError` is unchanged and still differs in the later versions.

All five original DOL hashes were verified. All five `all_source` builds and
native strict retail checksum targets pass. Independent all-retail links and
links substituting both save units also reproduce each original DOL byte for
byte, checking final relocations and data placement beyond objdiff scores.

Every source object outside the three edited units is byte-identical to its
baseline. EN, EN rev1, and JP retain identical allocated bytes, section
alignment, and symbol positions, accounting for the zero constant's rename and
compiler-generated anonymous symbol numbering. PAL's only added non-code
storage is the evidenced language table and its natural alignment. No compiler
profiles, TU boundaries, or generated source paths change.
