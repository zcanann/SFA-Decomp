# Title-menu language setup

`dlls/engine/52_n_attractmode/n_attractmode.c` now matches all eight functions
and all data in all five retail versions. The later builds contain additional
menu/save behavior, rather than requiring a different compiler profile.

## Recovered flow

PAL v1.0 and PAL rev1 use a four-state language setup sequence:

| State | Behavior |
| --- | --- |
| 0: none | Ordinary title-menu operation. |
| 1: requested | Select title entry 3 and enter its options panel once the selection fade finishes, without requiring a menu confirmation. |
| 2: open | The language panel is open; returning through `TitleMenu_initialise` advances to state 3. |
| 3: restore | Clear the state, preserve the selected language and subtitle setting, load/create options, restore the two settings, and apply them. |

The request originates when the attract movie is dismissed with save options
still pending (`gSaveGameEnabled == 0xFF`), `loadGameOptions` returns zero, and
`OSGetLanguage` reports Dutch. Other console languages use the existing save
creation path. If restoration needs to create a save file and saving remains
enabled, PAL writes the preserved settings through `saveGameOptions`.

PAL rev1 additionally calls `loadGameOptions` when `cardCreateSaveFile(1)`
returns nonzero at all three creation sites. A private inline helper
expresses that repeated operation. PAL v1.0 and the other versions retain their
ordinary creation call.

EN rev1 contains the extra state word and only the state-1 menu-confirmation
check. Its title-menu body has no corresponding stores or PAL setup flow.
EN v1.0 and JP have neither the word nor the check. The source preserves these
differences without extending PAL behavior to the other versions.

## Data and callees

The state is a real four-byte `.sbss` object between the prepare-pending and
autoplay flags. All addresses below come from verified retail r13-relative
loads/stores, not normalized objdiff relocations:

| Version | Language setup state | Autoplay flag |
| --- | --- | --- |
| EN rev1 | `803DE294` | `803DE298` |
| PAL v1.0 | `803DEE14` | `803DEE18` |
| PAL rev1 | `803DEFCC` | `803DEFD0` |

PAL has nine state references and three autoplay references across `TitleMenu_run`
and `TitleMenu_initialise`; EN rev1 has one state reference and three autoplay
references. The relevant functions preserve r13. PAL v1.0's old autoplay name
at `803DEE1A` was two bytes past the actual storage; PAL rev1 had only an unnamed
label at the correct address. The state definition restores the later versions'
source layout without artificial padding or section overrides.

`SaveData` byte 1 is now `languageIndex`, with its offset and byte-2
`subtitlesEnabled` asserted beside the existing layout. PAL's default-options
routine writes byte 1 according to the console language; `loadSaveSettings`
uses it to index the game-language mapping. The title menu saves and restores
both bytes around option loading. Retail clears `0xE4` bytes for this record,
matching the asserted `SAVE_DATA_SIZE`.

Previously unnamed PAL calls now use the evidenced APIs:

| API | PAL v1.0 | PAL rev1 | Evidence |
| --- | --- | --- | --- |
| `loadGameOptions` | `800E8990` | `800E8988` | Calls `maybeTryLoadSave(saveData)`, checks `optionsValid`, invokes the default-options routine when needed, and returns the load result. |
| `saveGameOptions` | `800E8968` | `800E8960` | Passes `saveData` to the options-writing memory-card path. |
| `OSGetLanguage` | `80245FF0` | `80246128` | Locks SRAM, reads its language byte at offset `0x12`, unlocks, and returns the byte. |

The title-menu change names those retail entry points and declares the PAL save
API. The save helper units remain incomplete. The SRAM accessors were subsequently
restored and their unit verified across all five versions; see
[SRAM language and video modes](sram_language_and_video_modes.md).

The movie-prepare panic line is also versioned from retail: `0x2FB` in EN v1.0/JP,
`0x33E` in EN rev1, `0x33A` in PAL v1.0, and `0x34D` in PAL rev1. Its constant
now belongs to the movie TU instead of the neighboring legacy header.

## Results and validation

| Version | Exact functions before → after | Exact code after | Exact data after |
| --- | --- | --- | --- |
| EN v1.0 / JP | 8 → 8 | 4,592 bytes | 572 bytes |
| EN rev1 | 6 → 8 | 4,604 bytes | 580 bytes |
| PAL v1.0 | 5 → 8 | 4,784 bytes | 580 bytes |
| PAL rev1 | 5 → 8 | 4,820 bytes | 580 bytes |

The three later matching manifests now include this unit. Each original DOL's
configured SHA-1 was verified. All five `all_source` builds and native strict
checksum targets pass. Independent all-retail links and links replacing only
the title-menu object also exactly reproduce all five DOLs.

Every other source object is byte-identical to its baseline. EN v1.0 and JP
retain identical allocated bytes, alignment, and symbol layout; the inline
helper renumbers one anonymous float symbol from `@486` to `@491`. There are no
compiler, optimization, TU-boundary, or generated-path changes.
