# ChapBits (`CHAPBITS.bin`)

> Source: [Rena Kunisaki's SFA wiki](https://github.com/RenaKunisaki/StarFoxAdventures/wiki/ChapBits). Reverse-engineering notes; not independently verified here.

The wiki page is short: `CHAPBITS.bin`, a disc-root file, is `0x14000` bytes and entirely zero
except two small regions:

```
00001ED0  00 00 00 00  00 00 00 00  00 00 00 00  01 00 00 00
00001EE0  00 00 00 01  00 00 00 01  00 00 00 01  00 00 00 01
```
```
00005660  00 00 00 00  00 00 00 00  01 00 00 00  08 00 04 2D
00005670  08 00 04 2D  08 00 04 2D  08 00 04 2D  00 00 00 00
```

- `0x42D` = 1069 (decimal).
- Rena's guess: "about 5 ints per GameBit - one per chapter?"
- Marked `TODO investigate this file` — never resolved further upstream.

## Verified against this repo's retail ISO

This repo ships the actual retail EN disc image
(`orig/GSAE01/Star Fox Adventures (USA) (v1.00).iso`), so the file can be checked directly instead
of taking the wiki's dump on faith:

- FST entry index 269: `CHAPBITS.bin`, flag `0` (file), disc offset `0x032859CC`, length `0x14000`.
  Confirmed against the game's own boot header (`fst_offset`/`fst_size` at DOL-header-relative
  `0x424`/`0x428`) — same FST-recovery approach as `tools/orig/dol_tables.py`.
- Extracting those `0x14000` bytes reproduces the wiki's hex dump byte-for-byte, and — going one
  step further than the wiki — **the rest of the file is confirmed all-zero**: across the whole
  `0x14000` bytes, the *only* non-zero bytes are inside the two windows above (`0x1EDC`-`0x1EEF` and
  `0x5668`-`0x567B`). There is no third region and no trailing data anywhere else in the file.
- Read as big-endian `u32` (the platform's native word order), each region resolves cleanly to
  **five consecutive 4-byte-aligned words**, not an arbitrary byte spray:
  - Region A (`0x1EDC`..`0x1EEC`, step 4): `0x01000000`, `1`, `1`, `1`, `1`.
  - Region B (`0x5668`..`0x5678`, step 4): `0x01000000`, `0x0800042D`, `0x0800042D`, `0x0800042D`, `0x0800042D`
    (the repeated word's low 16 bits are `0x042D` = 1069, matching Rena's note).
  - Both regions share the exact same shape: one `0x01000000` "marker" word, then four identical
    words. That symmetry is a genuine structural clue (and lines up with Rena's "5 ints" guess), but
    what the marker and the repeated value *mean* is still unestablished — this doc doesn't guess
    further than that.

## In this codebase

- **`CHAPBITS.bin` itself: not found.** A repo-wide, case-insensitive search of `src/`, `include/`,
  `config/`, `docs/`, and `tools/` for `chapbits` turns up nothing. The literal ASCII string
  `CHAPBITS` also does not appear anywhere in `orig/GSAE01/sys/main.dol` (checked directly), so no
  code path opens it by a literal path string embedded in the binary.
- **Not in the recovered runtime file-ID table either.** `docs/orig/dol_tables.md` /
  `tools/orig/dol_tables.py` recover an 88-entry generic loader table (`0x00`-`0x57`, e.g.
  `BLOCKS.bin`, `DLLS.bin`, `TEXPRE.bin`, ...) from `main.dol`. Re-running that tool against an
  `fst.bin` extracted from this repo's own ISO with `--search chap` returns **no matching entries**.
  So if the game reads this file at all, it isn't through that table.
- **Unlikely to be the `gGameBitTable` master descriptor array.** `mainGetBit`/`mainSetBits`
  (`src/main/gameloop.c:409`/`:479`) index a runtime table `gGameBitTable` (pointer,
  `.sbss:0x803DCADC`) bounded by `gGameBitCount` (`u16`, `.sbss:0x803DCAD8`), and the bit id is
  masked to `& 0xfff` (max 4096 ids) before any lookup. A 4-byte-per-id descriptor array for that
  many ids would be at most `0x4000` bytes — a quarter of `CHAPBITS.bin`'s `0x14000`. That doesn't
  rule out a connection, but on size alone `CHAPBITS.bin` doesn't look like a good fit for that
  table's backing data.
- **Two related-but-distinct "chapter" mechanisms exist in this codebase — neither is this file:**
  - The persistent quest/story bit engine: `gGameBitTable` / `gGameBitCount` / `gGameBitSaveData`,
    `mainGetBit(int eventId)` / `mainSetBits(int eventId, int value)` in `src/main/gameloop.c`
    (declared `extern` at lines 399-401, implemented 409-472 and 479+). This is the save-file-resident
    bit store documented in `include/main/gamebits.h`'s `enum GameBitId`. Several of that enum's
    imported-from-Rena entries carry a `"table 0"`..`"table 3"` comment (Rena's own gamebits.xml
    terminology, e.g. `GAMEBIT_SH_KilledBloop1 = 0x5, /* table 1 */`); `mainGetBit`/`mainSetBits`
    independently switch on a bank field (`gGameBitTable[id*4+2] >> GAMEBIT_FLAG_BANK_SHIFT`, values
    0-3) into four `gGameBitSaveData` base offsets (`+0xef0`, `+0x564`, `+0x24`, `+0x5d8`). Whether
    Rena's "table N" and this project's bank 0-3 are the *same* numbering has not been
    cross-checked here — flagging it as a plausible but unconfirmed link, not a verified one.
  - A debug/cheat **chapter-select** menu: `SAVE_SELECT_PANEL_CHAPTER_SELECT` in
    `src/main/dll/dll_0035_saveselectscreen.c` (`saveSelectGoToChapterSelect`, `SaveSelectScreen_run`)
    and `saveSelectSetSlot` in `src/main/dll/dll_43.c`. It lets a save slot warp straight to one of
    six chapters by loading a canned `/savegame/save%d.bin` file (`sSaveGameBinPathFormat`). This is
    a title-screen UI feature backed by bundled save files, not a disc-root asset, and has no
    connection to `CHAPBITS.bin` beyond the word "chapter".
  - `include/main/gamebits.h` also carries several per-area `*_ActNo` ids (e.g. `GAMEBIT_SH_ActNo`,
    `GAMEBIT_NW_ActNo`, `GAMEBIT_WM_ActNo`, 17 areas total), each `size 4` (a 4-bit act/chapter
    counter per area) — the closest conceptual analog to "one value per chapter" in this codebase,
    but again backed by the GameBit save engine above, not by `CHAPBITS.bin`.

## Ready-to-adopt code

None. The page defines no settled enum, flag table, or id list — just two raw data windows whose
field semantics are still an open `TODO` even upstream. Encoding an enum/struct for it now would be
inventing meaning that hasn't been established. Revisit this section if a future pass traces the
code that actually opens `CHAPBITS.bin` (or proves it's dead/unused retail data).
