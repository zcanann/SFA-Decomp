# Cheat Tokens

> Source: [Rena Kunisaki's SFA wiki](https://github.com/RenaKunisaki/StarFoxAdventures/wiki/CheatTokens). Reverse-engineering notes; not independently verified here.

There are 8 Cheat Tokens, none of which unlock actual cheats by themselves. Each token, when
placed in the Well, sets a [GameBit](../../include/main/gamebits.h) and displays a message.

## Where and What

| Collected Bit | Used Bit | Unlocked Bit | Text ID | Unlocks | Location |
|---------------|----------|--------------|---------|---------|----------|
| 0DDC | 0F34 | 0DE5 | 0524 | Display Credits | ThornTail Shop |
| 0DE2 | 0F3A | 0DEB | 0524 | Sepia GFX Mode | Cape Claw |
| 0DDE | 0F36 | 0DE7 | 0524 | Music Test | Ice Mountain |
| 0DDD | 0F35 | 0DE6 | 0571 | Dinosaur (see below) | Moon Mountain Pass |
| 0DE0 | 0F38 | 0DE9 | 056E | nothing | LightFoot Village |
| 0DE3 | 0F3B | 0DEC | 056F | nothing | Ocean Force Point |
| 0DDF | 0F37 | 0DE8 | 0570 | nothing | Volcano Force Point |
| 0DE1 | 0F39 | 0DEA | 0572 | nothing | SnowHorn Wastes |
| 0DE4 | 0000 | 0DED | 0000 | nothing | Nowhere (unused token) |

- **Collected Bit**: whether the token has been collected.
- **Used Bit**: whether the token has been used (removes it from the inventory).
- **Unlocked Bit**: also set when the token is used; never read?
- **Text ID**: which text is displayed.
- **Unlocks**: which cheat is unlocked.
- **Location**: where the token is found.

The "Unlocked" bits seem to be unused, as there's a separate field in the save file used to track
which cheats are unlocked (offset 0x10 in the global save settings). This field is one byte with
the bits:

- 0x01: Show Credits
- 0x02: Sepia Mode
- 0x04: Music Test
- 0x08: Dino Language
- 0x10: Unused 1
- 0x20: Unused 2

The functions responsible for accessing this field mask the value with 0x3F, implying there were
originally 6 cheats.

Since the unlock flags are stored in the global settings (separate from individual save files),
unlocking cheats on any file unlocks them for all files. Unlocking them a second time does
nothing.

## Texts

The first 3 rows display the message "Cheat Activated" (Text ID 0x524).

The others are:

### 0x56E (LightFoot Village token)
```
The Well looks into your future...
A friend who has left, still cares about you.
The bond of your friendship still remains.
He will soon appear before you.
And you should accept him with all your heart.
```

### 0x56F (Ocean Force Point token)
```
The Well looks into your future...
There is sorrow ahead.
A close friend does not have much time left.
It will be hard to accept but you will grow.
```

### 0x570 (Volcano Force Point token)
```
The Well looks into your future...
Fox...I can see you have matured into a strong leader.
I am always there with you.
Never give up...Trust your instincts...My son...
```

### 0x572 (SnowHorn Wastes token)
```
The Well looks into your future...
His Life-Force is strong. His existence is like a virus.
I can hear his breath in every corner of space.
He will not only use the evil heart of others.
But can also corrupt those that are good.
```

### 0x571 (Moon Mountain Pass token)
This token behaves differently depending on what language the game is running in. In Japanese, it
displays the message:

- 井戸の底から声が聞こえる…
- … … … …
- おぬしはあの娘と出会う運命だったのじゃ。
- お前たちが力を合わせる事によって
- いずれこの宇宙に
- 大いなる平和をもたらすじゃろう……
- 今はピンとこんかもしれんがな…。

Rough translation:

- I hear a voice from the bottom of the well...
- ... ... ...
- You were destined to meet that girl.
- By joining forces,
- you will one day bring great peace to this universe...
- It may not ring a bell right now, but...

In other languages, it unlocks the Dinosaur Language cheat and displays the "Cheat Activated" text
(the ID is overridden). This cheat can't be unlocked when playing in Japanese, probably because it
wouldn't do anything for Japanese text.

(TODO, per the original wiki: how do the other European languages/EU releases handle this? There
are claims online that some have one and some have the other.)

The corresponding (unused) English text for this ID is:

- The Well looks into your future...
- You are meant to be together. It was your destiny.
- Together as one, you will bring peace.

## Unused Things

The tables for Collected Bit and Unlocked Bit have 9 entries; the tables for Used Bit and Text ID
have only 8. A theoretical 9th token would read unrelated data following the table, which happens
to be zero in both cases.

## In this codebase

This page maps almost completely onto one already-decompiled object and a set of already-imported
`GameBitId` enum entries. Everything below was verified by reading the listed source.

### The Well object and its quest-bit table

- The Well itself is **DLL 0x263**, `src/main/dll/dll_0263_gmmazewell.c` (`GM_MazeWell_init` /
  `_update` / `_render` / `_free` / `_getExtraSize` / `_SeqFn`, and
  `gGmMazeWellObjDescriptor` at `.data:0x8032A788`). Its header comment already describes exactly
  this mechanic: "the well watches a fixed set of nine quest/event game bits... when one fires it
  grants that row's reward bits, optionally unlocks a cheat (rows 0-2), records the row's
  dialogue id as a pending trigger, and runs sequence 0." (Row 3, Dino Language, also unlocks a
  cheat via a `case 3:` fallthrough — see "The language-dependent Moon Mountain Pass token" below.)
  - Per `docs/wiki/Objects.md`'s own two-letter-DLL-prefix table, `GM` = "Game Maze (cheat
    tokens)" — this repo's own prior wiki import already names this DLL family after exactly this
    feature.
  - `dll_0263_gmmazewell.c` includes `main/dll/DR/dr_shared.h` (the Dragon Rock shared-declaration
    header; `DR` = DragonRock per `docs/wiki/Objects.md`/`AudioStreams.md`), even though the
    `.c` file itself lives outside the `DR/` subfolder — consistent with (but not proof of) the
    Well physically being sited at Dragon Rock. Not independently confirmed against placement/map
    data in this pass.
- The wiki's "table" (9 watched bits × {reward bit, follow-up bit, dialogue id}) is the flat
  `s16 lbl_8032A730[44]` array, defined at `src/main/dll/DR/dll_0250_ktrex.c:1961` (`.data:0x8032A730`,
  size `0x58` per `config/GSAE01/symbols.txt`) and declared `extern` in
  `include/main/dll/DR/dr_shared.h:154`. Its 44 raw values are **byte-identical** to the wiki's
  table read column-major:
  ```
  { 0x0ddc, 0x0de2, 0x0dde, 0x0ddd, 0x0de0, 0x0de3, 0x0ddf, 0x0de1, 0x0de4, 0x0000,   // Collected bits (+ pad)
    0x0de5, 0x0deb, 0x0de7, 0x0de6, 0x0de9, 0x0dec, 0x0de8, 0x0dea, 0x0ded, 0x0000,   // Unlocked bits (+ pad)
    0x0f34, 0x0f3a, 0x0f36, 0x0f35, 0x0f38, 0x0f3b, 0x0f37, 0x0f39, 0x0000,           // Used bits (8, no pad)
    0x0524, 0x0000, 0x0524, 0x0000, 0x0524, 0x0000, 0x0571, 0x0000, 0x056e, 0x0000,
    0x056f, 0x0000, 0x0570, 0x0000, 0x0572 };                                        // Text IDs, viewed as s32
  ```
  `GM_MazeWell_update` (`src/main/dll/dll_0263_gmmazewell.c:77`) reads it as `s16* questBits`
  (watched/reward/follow-up columns) and simultaneously as `s32* questBits32` (the dialogue-id
  column, since text IDs there are stored as full words) — the same array, two views, exactly the
  wiki's implied dual bit-width layout.
- **Unused 9th-row footnote, confirmed byte-exact**: the update loop runs for `i` in
  `[0, QUEST_BIT_COUNT)` with `QUEST_BIT_COUNT = 9`, and row 8's dialogue id is read as
  `questBits32[i + QUEST_DIALOGUE_BASE32]` = `questBits32[22]`. The dialogue-id view only has 22
  `s32` elements (44 `s16` / 2), so index 22 reads one word **past** the declared array — which
  lands exactly on the first word of the very next `.data` symbol,
  `gGmMazeWellObjDescriptor` (`.data:0x8032A788`, immediately adjacent per `symbols.txt`), whose
  first field is `0x00000000`. This is a byte-exact confirmation of the wiki's "reads unrelated
  data following the table, which happens to be zero" footnote — the out-of-bounds read only
  matters if gamebit `0x0DE4` (the unused 9th token's "Got" bit) is ever set, which nothing in the
  game does.

### The GameBits — already imported

All 26 bits from the "Where and What" table are already present as named entries in
`include/main/gamebits.h`'s `enum GameBitId`, using the row order (0=ThornTail/Credits ...
8=unused/Nowhere) as the numeric suffix:

| Wiki column | Enum names (`include/main/gamebits.h`) |
|---|---|
| Collected Bit | `GAMEBIT_ITEM_CheatToken0_Got` (0xDDC) … `GAMEBIT_ITEM_CheatToken8_Got` (0xDE4) |
| Unlocked Bit | `GAMEBIT_Cheat0_Credits_Unlocked` (0xDE5) … `GAMEBIT_Cheat8_Unlocked` (0xDED) |
| Used Bit | `GAMEBIT_ITEM_CheatToken0_Used` (0xF34) … `GAMEBIT_ITEM_CheatToken5_Used` (0xF3B) |

`GAMEBIT_ITEM_CheatToken8_Got`'s comment already notes "No corresponding UsedCheatToken8? doesn't
show up in C menu" — an independent confirmation of the wiki's "unused token" row written before
this cross-reference pass.

The music/active gamebit for the Well room itself (`GAMEBIT_MAZEWELL_ACTIVE = 0xEFC`, set in
`GM_MazeWell_init`/cleared in `GM_MazeWell_free`, gating `Music_Trigger(0x36, ...)`) is **not** yet
in the `GameBitId` enum — it's currently a private `#define` local to
`dll_0263_gmmazewell.c`. See "Ready-to-adopt code" below.

### The global cheat-unlock byte (save offset 0x10)

Confirmed **field-offset-exact**: `include/main/dll/savedata_struct.h`'s `SaveData` struct has
`u32 registeredDebugOptions` immediately at offset `0x10` (2+1+1+1+1+1+1+1+1+1+1+1+3 bytes of
prior fields), matching the wiki's "offset 0x10 in the global save settings" claim exactly — this
repo just types it as a `u32` bitmask rather than "one byte" (both readings are compatible; only
the low 6 bits documented by the wiki are ever set).

- `registeredDebugOptions`: which cheats have ever been unlocked (wiki's "Unlocked" concept).
- `enabledDebugOptions`: which unlocked cheats are currently turned **on** in the Options menu
  (a second bitmask, same struct, immediately following at `0x14`) — this is the wiki's implicit
  distinction between "unlocked" and "active/enabled" made concrete.

Accessors, canonical home `src/main/dll/dll_0015_curves.c`:
- `saveFileStruct_unlockCheat(u8 idx)` / `isCheatUnlocked(u8 idx)` (lines ~1836-1850) — set/test a
  bit in `registeredDebugOptions`.
- `saveFileStruct_setCheatActive(u8 idx, u8 active)` / `saveFileStruct_isCheatActive(u8 idx)`
  (lines ~1743-1760, ~1852-1865) — `setCheatActive` refuses to set the enabled bit unless the
  matching `registeredDebugOptions` bit is already set; `isCheatActive` requires *both* bits.

Per `config/GSAE01/splits.txt`, these four functions (`.text:0x800E7E40`-`0x800E7EFC`) belong to
the `dll_0015_curves.c` unit (`0x800E5434`-`0x800E8100`). The identically-named functions also
present in `src/main/dll/dll_0017_savegame.c:677-692` are a **separate, distinct compiled copy**
at different addresses (`dll_0017_savegame.c` occupies `0x800E8100`-`0x800EA174`, i.e. immediately
after `dll_0015`) — a "drift duplicate": same source shape, backed by loose globals
(`gGameplayRegisteredDebugOptions`, etc., declared `extern` in `include/main/dll/gameplay.h`)
instead of the `SaveData` struct. The header comments on `dll_0060_dll60func0.c`,
`dll_0061_dll61func0.c`, `dll_0073_dll73func0.c` and `dll_0074_dll74func0.c` independently
document further drift-duplicated copies of this same helper family across the DLL 0x005E-0x007B
"gameplay" range, all citing `dll_0015_curves` as the retail/canonical home.

The wiki's "mask with 0x3F, implying 6 cheats" detail was **not found** — no decompiled function
in this pass ANDs `registeredDebugOptions`/`enabledDebugOptions` with `0x3F`. It may live in a
not-yet-matched function, or in one of the drift-duplicate copies not read in this pass.

### Which cheat index is which

The 4 real cheats' `cheatId` (0-3) is confirmed by call sites, independent of the Well:

- **0 = Show Credits**: `src/main/dll/prof.c`'s `optionsMenu_openGeneralPanel` loop (`cheatId = 0`)
  calls `saveFileStruct_isCheatActive((u8)cheatId)` directly for `cheatId == 0`.
- **1 = Sepia GFX Mode**: same loop special-cases `cheatId == 1` to read
  `Rcp_GetColorFilterEnabled()` instead of the save-file bit — Sepia mode's "on/off" is tracked by
  the color-filter renderer flag directly, not through `enabledDebugOptions`.
- **2 = Music Test**: `optionsMenu_openAudioPanel` (`src/main/dll/prof.c`) calls
  `isCheatUnlocked(2)` to reveal an extra audio-panel entry (a sound-test row).
- **3 = Dino Language**: named `#define LANGUAGE_MENU_CHEAT_ID 3` in `src/main/dll/dll_4d.c`;
  the same literal `3` is passed to `saveFileStruct_isCheatActive`/`saveFileStruct_setCheatActive`
  in `src/main/textrender.c:593` and `src/main/dll/dll_0037_optionsscreen.c:262`.

`GM_MazeWell_update`'s reward switch (`case 0: case 1: case 2:` unconditionally, `case 3:` falling
through from a Japanese-only branch) uses the loop index `i` directly as `cheatId`, which lines up
1:1 with the row order above (row0=Credits, row1=Sepia, row2=MusicTest, row3=Dino).

### The language-dependent Moon Mountain Pass token, confirmed

`GM_MazeWell_update` branches on `lbl_803DC968` (`src/main/dll/dll_0263_gmmazewell.c:129`), which
`src/main/textrender.c:2955-2970` sets to `1` exactly when `OSGetFontEncode() == 1` (the
Shift-JIS/Japanese font) and to `0` for encoding `0` (`curLanguage` is likewise set to `4` vs. `0`
in the same branch) — i.e. it is an "is Japanese" flag, matching the wiki's language-conditional
description exactly:

- Japanese (`lbl_803DC968 != 0`): the follow-up bit and `pendingDialogue` are set for every
  matched row unconditionally (outside the `switch`), so row 3 still queues its normal dialogue id
  (`questBits32[3 + 14]` = the `0x571` Japanese fortune text). But the reward-bit +
  `saveFileStruct_unlockCheat` block is gated by `switch (i) { case 0: case 1: case 2: ...}` with
  **no `case 3:`** in this branch, so row 3 never unlocks a cheat while playing in Japanese —
  exactly "This cheat can't be unlocked when playing in Japanese."
- Non-Japanese (`lbl_803DC968 == 0`): row 3 (`case 3:`) overrides `state->pendingDialogue` to
  `MAZEWELL_DEFAULT_DIALOGUE` (`#define MAZEWELL_DEFAULT_DIALOGUE 1316`, i.e. **0x524** — the
  "Cheat Activated" text id) before falling through into the same reward-granting code as rows
  0-2, unlocking cheat index 3 (Dino Language). This is byte-for-byte the wiki's "unlocks the
  Dinosaur Language cheat, and displays the 'Cheat Activated' text (the ID is overridden)."

The Dino Language text transform itself is `translateToDinoLanguage` (`src/main/textrender.c:1040`,
declared at line 519), invoked from the string-rendering path only when
`saveFileStruct_isCheatActive(3)` is true and `curLanguage != 4` (i.e. not Japanese) — consistent
with the cheat's text substitution never applying to Japanese text.

## Ready-to-adopt code

```c
/* Cheat option indices (registeredDebugOptions/enabledDebugOptions bit index, aka cheatId).
 * Confirmed by call sites: prof.c's optionsMenu_openGeneralPanel loop (0=Credits via
 * saveFileStruct_isCheatActive, 1=Sepia via Rcp_GetColorFilterEnabled), prof.c's
 * optionsMenu_openAudioPanel (2=Music Test via isCheatUnlocked), dll_4d.c's
 * LANGUAGE_MENU_CHEAT_ID / textrender.c / dll_0037_optionsscreen.c (3=Dino Language).
 * Wiki: CheatTokens "global save settings, offset 0x10" bit list. Bits 4/5 never assigned
 * in this codebase (matches the wiki's "mask 0x3F, implying 6 cheats" note - the other two
 * planned cheat slots were not found as decompiled code in this pass). */
enum CheatId
{
    CHEAT_SHOW_CREDITS  = 0,
    CHEAT_SEPIA_MODE    = 1,
    CHEAT_MUSIC_TEST    = 2,
    CHEAT_DINO_LANGUAGE = 3
};
```

```c
/* GM_MazeWell (DLL 0x263) quest-bit table row indices, into lbl_8032A730[] /
 * gQuestBitTable (src/main/dll/DR/dll_0250_ktrex.c, consumed by
 * src/main/dll/dll_0263_gmmazewell.c). Matches CheatId above for rows 0-3; rows 4-7 grant
 * no cheat ("nothing" in the wiki's Unlocks column); row 8 is the unused/dead 9th token. */
enum QuestWellRow
{
    QUESTWELL_CREDITS        = 0, /* ThornTail Shop   -> CHEAT_SHOW_CREDITS */
    QUESTWELL_SEPIA          = 1, /* Cape Claw        -> CHEAT_SEPIA_MODE */
    QUESTWELL_MUSIC_TEST     = 2, /* Ice Mountain     -> CHEAT_MUSIC_TEST */
    QUESTWELL_DINO_LANGUAGE  = 3, /* Moon Mtn Pass    -> CHEAT_DINO_LANGUAGE (non-Japanese only) */
    QUESTWELL_LIGHTFOOT      = 4, /* LightFoot Village -> nothing */
    QUESTWELL_OCEAN_FP       = 5, /* Ocean Force Point -> nothing */
    QUESTWELL_VOLCANO_FP     = 6, /* Volcano Force Point -> nothing */
    QUESTWELL_SNOWHORN       = 7, /* SnowHorn Wastes  -> nothing */
    QUESTWELL_UNUSED         = 8  /* Nowhere - dead; dialogue lookup reads OOB into
                                    * gGmMazeWellObjDescriptor's leading 0 word */
};
```

```c
/* Add to include/main/gamebits.h's enum GameBitId (between GAMEBIT_WarpRelated0EFB = 0xEFB and
 * GAMEBIT_PlayerInShop = 0xEFE - slot 0xEFD stays a gap). Currently a private
 * #define GAMEBIT_MAZEWELL_ACTIVE 0xefc in dll_0263_gmmazewell.c; gates Music_Trigger(0x36, ..)
 * and the Well's hitbox-disable state. Set in GM_MazeWell_init, cleared in GM_MazeWell_free. */
GAMEBIT_MAZEWELL_ACTIVE = 0xEFC, /* table 0; Music_Trigger(0x36) + Well active/hitbox state */
```
