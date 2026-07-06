# Gametext

> Source: [Rena Kunisaki's SFA wiki](https://github.com/RenaKunisaki/StarFoxAdventures/wiki/Gametext). Reverse-engineering notes; not independently verified here.

In-game text is stored in `gametext/[MapName]/[Language].bin`. These files contain the text
itself, the font graphics, and instructions on how to assemble the font texture from those
graphics.

## File Format

```C
u32 numCharStructs;
characterStruct[numCharStructs];

u16 numTexts;
u16 strDataLen;
gametextStruct[numTexts] texts;

u32 numStrings;
u32 strOffset[numStrings]; //offsets into `strings`
char[] strings[strDataLen];

u32 unknownLen;
u8 unknownData[unknownLen]; //all bytes are 0xEE in every file
//this might be referenced later by the font code?

struct {
    u16 texFmt; //destination texture format
    u16 pixFmt; //bits per pixel of font image
    u16 width;
    u16 height;
    byte pixels[];
} fontTextures[]; //ends when width == 0 && height == 0
```

### characterStruct: Character Data

Assigns positions within the font texture to character codes. The file
`gametext/Boot/English.c.new` contains the struct definition:

```C
typedef struct {
        UCS4            character;      // unicode number
        unsigned short  xpos;           // coordinate of leftmost texel in font bitmap
        unsigned short  ypos;           // coordinate of topmost texel in font bitmap
        signed char     left;           // spacing
        signed char     right;          // spacing
        signed char     top;            // spacing
        signed char     bottom;         // spacing
        unsigned char   width;          // size
        unsigned char   height;         // size
        unsigned char   font;           // Index into GameTextFonts[] in GameTextData.h
        unsigned char   texture;        // Index into Textures[] in the binary file
} characterStruct;
```

### gametextStruct: Messages

Defines the dialogue messages. `English.c.new` also contains this struct definition:

```C
typedef struct {
        unsigned short  identifier;     // which game text is this
        unsigned short  numPhrases;     // how many phrases this text has
        unsigned char   window;         // preferred window
        unsigned char   alignH;         // horizontal alignment
        unsigned char   alignV;         // vertical alignment
        unsigned char   language;       // LANGUAGE_xxx from GameTextData.h
        UTF8            **phrases;      // pointer to <numPhrases> pointers to localised strings
} gametextStruct;
```

### Strings

After the `gametextStruct` array is a u32 giving the number of strings, followed by one u32
offset per string, followed by the UTF-8 strings themselves. The total size of the string data
(excluding the offset table) is given by the `strDataLen` value before the `gametextStruct`
array.

Each offset is relative to the beginning of `strings`. Each string is null-terminated, but may
contain control codes that include null bytes, so it's necessary to parse those to read the
entire string.

The strings are grouped by their decimal IDs:

* 0 - 9999: Generic text.
  * 244+: Hint texts tied to GameBits.
* 10000 - 19999: Descriptions shown in pause menu or PDA.
* 20000 - 29999: Sequence text. In many cases, sequence N uses text (N + 20000).

The highest valid ID is 21352. These groupings don't seem to serve any purpose in the game and
were probably just used during development to organize them.

### Unknown

This block begins with its length as a u32, and is just filled with `0xEE`. The game skips this
section when parsing the file, but appears to copy it elsewhere as well. The game seems to run
just fine if this section is truncated to a length of zero.

### Font Textures

This section contains multiple texture graphics, which are referenced by the character data.

The distance from the beginning of one texture to the beginning of the next is given by:

`length = (((width * height * pixFmt) >> 4) * 2) + 4`

The texture format is mapped: 2 => 0, 1 => 5; the result is a standard GameCube texture format
ID:

| Fmt | Name |
| --- | ---- |
| 00 | I4 |
| 01 | I8 |
| 02 | IA4 |
| 03 | IA8 |
| 04 | RGB565 |
| 05 | RGB5A3 |
| 06 | RGBA32 |
| 08 | C4 |
| 09 | C8 |
| 0A | C14X2 |
| 0E | BC1 / CMPR |

#### Font IDs

Within the files, font textures are assigned a font ID:

* Font 0: Japanese and some Latin characters, rendered in monochrome. Used for Japanese text.
* Font 1: Does not exist.
* Font 2: Button icons.
* Font 3: Flags.
* Font 4: Latin characters, rendered in monochrome. Used for non-Japanese text.
* Font 5: Character faces.

Font 4 appears to be "EurostileBQ-Regular.otf" and Font 0 appears to be "FOT-RodinNTLG Pro B.otf",
both at 20pt. The others are custom made.

Note that Japanese text includes some Latin characters, but uses the Fullwidth versions, eg 'Ａ'
(U+FF21) rather than 'A' (U+0041). (These may appear identical in your browser.)

#### Font Slots

Four fonts can be loaded at a time. Each slot is used for a particular purpose:

* Slot 0: The currently loaded font for dialogue (various directories).
* Slot 1: The currently loaded font for a cutscene (directory `Sequences`).
* Slot 2: The error message font (directory `Boot`).
* Slot 3: The HUD font (directory `Link`).

#### Font Loading

Each font slot has two textures: one monochrome (for character graphics - fonts 0, 4) and one
colored (for icons - fonts 2, 3, 5).

To load a GameText file, each of these is assigned a blank texture. The graphics from the file
are copied into the textures as directed by the `characterStruct` array. Each entry specifies a
font ID, and which of the two textures contain the character.

This makes it impossible to use the Japanese flag, since both it and the joystick icon are
assigned the letter J. (TODO: investigate how the European versions fix this.)

## Control Codes

Within the messages, some control codes are supported. Each code is a UTF-8 Private Use
character, followed by some number of 16-bit parameters. Note that the parameters can contain
null bytes, so it's necessary to decode these to find the actual end of the string.

| Code | UTF-8 Encoding | Description | Param1 | Param2 | Param3 | Param4 |
| ---- | -------------- | ----------- | ------ | ------ | ------ | ------ |
| E000 | EE 80 80 | Seq Id | ID | - | - | - |
| E018 | EE 80 98 | Seq Time | ? | Time | ? | - |
| E020 | EE 80 A0 | Hint ID | ID | - | - | - |
| F8F2 | EF A3 B2 | ? unused | ? | ? | - | - |
| F8F3 | EF A3 B3 | ? unused | - | - | - | - |
| F8F4 | EF A3 B4 | Set Scale | Scale | - | - | - |
| F8F5 | EF A3 B5 | ? unused | ? | - | - | - |
| F8F6 | EF A3 B6 | ? unused | ? | - | - | - |
| F8F7 | EF A3 B7 | Set Font | Font | - | - | - |
| F8F8 | EF A3 B8 | Justify Left | - | - | - | - |
| F8F9 | EF A3 B9 | Justify Right | - | - | - | - |
| F8FA | EF A3 BA | Justify Center | - | - | - | - |
| F8FB | EF A3 BB | Justify Full | - | - | - | - |
| F8FC | EF A3 BC | ? unused | - | - | - | - |
| F8FD | EF A3 BD | ? unused | - | - | - | - |
| F8FE | EF A3 BE | ? unused | - | - | - | - |
| F8FF | EF A3 BF | Set Color | Red | Green | Blue | Alpha |

* Seq Id: Unknown purpose. Parameter is the ID of the sequence that displays this text. Changing
  it doesn't seem to have any effect. (Possibly leftover debug info)
* Seq Time: Sets timing parameters for displaying this text in a sequence.
  * Param 0: Unknown. Usually 0, sometimes 1. Changing to 1 prevents text from appearing.
  * Param 1: When to display (number of seconds since start of sequence). (XXX verify units)
  * Param 2: Unknown, maybe controls fade-in speed?
  * general pattern is bbbb increases with each phrase unless aaaa=1
  * the text stays until replaced by another; the game removes texts by replacing them with a
    single space (sequences also begin with a single-space text with all params set to 0)
* Hint ID: Found at the start of the hint texts shown on the Continue screen and Slippy's Advice.
  The game doesn't seem to actually use this code for anything.
  * With each of these texts, the first phrase is the description shown on the Continue screen
    after you've completed it (eg "Discovered Krystal's Staff") and the rest are the hint shown
    in the Slippy's Advice section of the PDA before you've completed it (eg "...Look out for
    something sticking out of the ground.").
  * Each of these is referenced by a GameBit.
* Set Scale: Set the font size. Parameter is an integer, where 256 = 100%.
* Set Font: Select a font to use from here on. Parameter is a font ID.
* Justify: Set the text justification mode.
* Set Color: Set the font and shadow colors. Params are r, g, b, a, with the high byte of each
  being unused.
  * There is another routine that interprets the params as two sets of rrgg, bbbaa, rrgg, bbaa,
    where the first two are text color and the next are shadow color. This might not actually be
    used?

### Icons

Icons are used by selecting the font and printing the corresponding character:

| Font | Char | Icon |
| ---- | ---- | ---- |
| 2 | A | A Button |
| 2 | B | B Button |
| 2 | C | C Stick |
| 2 | J | Joystick |
| 2 | L | L Trigger |
| 2 | R | R Trigger |
| 2 | S | Start Button |
| 2 | X | X Button |
| 2 | Y | Y Button |
| 2 | Z | Z Button |
| 3 | D | German flag |
| 3 | F | French flag (mirrored) |
| 3 | I | Italian flag |
| 3 | J | Japanese flag |
| 3 | S | Spanish flag |
| 5 | T | Tricky face |
| 5 | c | Slippy face |
| 5 | n | King EarthWalker face |
| 5 | y | ThornTail face |

Not all icons are available in all maps/languages. The English version, lacking the language
select feature, doesn't include any flag for the English language. (European versions use a
British flag, and correct the French flag.)

## Sequences

Under `gametext/Sequences/` is GameText files used by sequences (see the Scripting wiki page).
These are in the same format as the others, except that some additional information is present
before the actual strings. (The offsets still point directly to the strings, so parsing works the
same as the other files.) This information contains, among other things, the string's length in
bytes.

Each file's name is an ID number (in decimal) and a language, eg `4_English.bin`.

### Sequence Lookup Table

At 0x802C8860 is a table, which assigns object sequence IDs to text sequence IDs. Running an
object sequence automatically loads the corresponding text sequence file.

If subtitles are turned off, the file won't be loaded, with the exception of the following object
sequences:

* 0x0069: SB_OpeningScene
* 0x006D: SB_YourAdventureBegins
* 0x0083: SB_MeetScales
* 0x0490: WM_KrystalLand
* 0x0493: WM_DinoOpenDoorTest1
* 0x0492: WM_DinoAfterTest1
* 0x0180: WM_ReleaseSpirit1
* 0x047F: SH_PickupStaff
* 0x001D: SH_StartStaffTutorial
* 0x0020: SH_DoneStaffTutorial
* 0x03C8: MMP_BringSpiritToPalace

(These are spoken in Dino Language, so they'd be difficult to understand otherwise.)

* ID: Object sequence ID
* Seq#: Text sequence ID
* Each entry also has a directory ID which is omitted here because every entry is 0x29
  (`Sequences`).
* Names are made up

| ID# | ID Dec | Seq# | Seq Dec | Name |
| ---- | -----: | ---- | ------: | ---- |
| 00D1 | 209 | 0004 | 4 | Tricky_ThatsMyMa |
| 04F7 | 1271 | 0006 | 6 | WM_RescueKrystal |
| 017C | 380 | 0009 | 9 | CF_FirstLanding |
| 004B | 75 | 000B | 11 | CF_GetPowerKey |
| 0285 | 645 | 000C | 12 | CF_PowerIsDown |
| 04EA | 1258 | 000E | 14 | |
| 0041 | 65 | 0010 | 16 | CF_ScalesAttackQueen |
| 047A | 1146 | 0011 | 17 | CF_RescueDino |
| 046C | 1132 | 0013 | 19 | CF_RescuedQueen |
| 01D7 | 471 | 0015 | 21 | CF_GiveFlute |
| 0477 | 1143 | 0016 | 22 | CF_GotSpellStone |
| 0205 | 517 | 0031 | 49 | CR_GetSpellStoneOut |
| 01B0 | 432 | 0037 | 55 | LV_MakeBirdStop |
| 0075 | 117 | 0038 | 56 | LV_StartTrackingTest |
| 02E5 | 741 | 003C | 60 | LV_StartStrengthTest |
| 0078 | 120 | 003D | 61 | LV_HonoraryMember |
| 0499 | 1177 | 003F | 63 | VFP_PeppyExplainForcePoint |
| 001E | 30 | 0042 | 66 | SH_WarpStone_Got3Stones |
| 000C | 12 | 0043 | 67 | SH_GiveMoonPassKey |
| 0027 | 39 | 0048 | 72 | NW_ReturnArtifact |
| 00A7 | 167 | 004B | 75 | CC_TrickyShooCloudRunner |
| 00AD | 173 | 0056 | 86 | CC_LightFootStayAway |
| 020F | 527 | 005A | 90 | MMP_WakeUp |
| 0023 | 35 | 005F | 95 | SH_WallCityNotReturned |
| 04C3 | 1219 | 0092 | 146 | |
| 00E4 | 228 | 00A6 | 166 | SH_TrickyDadIsGateKeeper |
| 001C | 28 | 00A7 | 167 | SH_GetLargeScarabBag |
| 00FE | 254 | 00AA | 170 | DIM_NPC_HelpGetFree |
| 0105 | 261 | 00AB | 171 | DIM_RescuedMammoth |
| 00FF | 255 | 00AD | 173 | DIM_LearnFlame |
| 0121 | 289 | 00AE | 174 | DIM_NPC_NeedFood |
| 056A | 1386 | 00AF | 175 | DIM_LostTricky |
| 00FA | 250 | 00B1 | 177 | DIM_NPC_NeedMore |
| 00FB | 251 | 00B2 | 178 | DIM_NPC_SoHungry |
| 00FC | 252 | 00B3 | 179 | DIM_NPC_LetsSmash |
| 01AA | 426 | 00B8 | 184 | LV_ItsATrap |
| 01AB | 427 | 00B9 | 185 | LV_BabiesClimbTrees |
| 016E | 366 | 00CA | 202 | DIM_MeetBelinaTe |
| 01A4 | 420 | 00CB | 203 | DIM_BelinaYouMadeIt |
| 007A | 122 | 00E6 | 230 | LV_ExplainTests |
| 0324 | 804 | 00F0 | 240 | |
| 0338 | 824 | 01F8 | 504 | DR_RescuedHighTop |
| 035A | 858 | 01FE | 510 | DR_GotLastSpellStone |
| 049C | 1180 | 0203 | 515 | DFP_AllStonesReturned |
| 053E | 1342 | 0205 | 517 | WC_DadOk |
| 0510 | 1296 | 020A | 522 | WC_GotSpellStone |
| 0544 | 1348 | 020B | 523 | WC_ByeTricky |
| 0462 | 1122 | 0265 | 613 | CF_FloorUnstable |
| 0532 | 1330 | 0288 | 648 | DIM_RescueBelinaTe |
| 008E | 142 | 0289 | 649 | CF_GrabTheStaff |
| 0282 | 642 | 028A | 650 | CF_LetsGetOut |
| 01DB | 475 | 028C | 652 | CF_GiveDisguise |
| 0045 | 69 | 028E | 654 | |
| 00E3 | 227 | 02A0 | 672 | SH_SavedEggs |
| 001F | 31 | 02B4 | 692 | SH_GateKeeperOpenPortal |
| 04E8 | 1256 | 02B9 | 697 | WM_FoxFirstWarpIn |
| 04E9 | 1257 | 02BA | 698 | WM_FoxMeetKrystal |
| 0127 | 295 | 02F1 | 753 | SP_WinScarabGame |
| 0128 | 296 | 02F2 | 754 | SP_LoseScarabGame |
| 0487 | 1159 | 02F3 | 755 | MMP_KrystalHelp |
| 03C4 | 964 | 02F4 | 756 | MMP_LookOut |
| 03C8 | 968 | 02F5 | 757 | MMP_BringSpiritToPalace |
| 0464 | 1124 | 4E21 | 20001 | CF_FindAllChildren |
| 0481 | 1153 | 4E22 | 20002 | CF_GetMeOut |
| 0483 | 1155 | 4E23 | 20003 | CF_GetMeOut2 |
| 053D | 1341 | 4E24 | 20004 | DIM_NPC_ThanksClimbOn |
| 02D8 | 728 | 4E25 | 20005 | CF_WakeUpInDungeon |
| 04FB | 1275 | 4E26 | 20006 | CC_NPC_HidMyGold |
| 04FE | 1278 | 4E27 | 20007 | CC_NPC_SharpClawCapturedCloudRunner |
| 0505 | 1285 | 4E28 | 20008 | CC_NPC_ShouldAbleFind |
| 0503 | 1283 | 4E29 | 20009 | CC_NPC_SecretChambers |
| 0052 | 82 | 4E2A | 20010 | SH_TrickyStayHere |
| 004F | 79 | 4E2B | 20011 | SH_NeedLantern |
| 0050 | 80 | 4E2C | 20012 | SH_GotLantern |
| 011B | 283 | 4E2D | 20013 | NW_BringFrostWeeds |
| 0571 | 1393 | 4E2E | 20014 | SH_NPC_SharpClawPutOutBeacons |
| 0074 | 116 | 4E2F | 20015 | LV_FailedTest |
| 007B | 123 | 4E30 | 20016 | LV_WinTrackingTest |
| 0383 | 899 | 4E31 | 20017 | LV_WinStrengthTest |
| 0384 | 900 | 4E32 | 20018 | LV_FailStrengthTest |
| 0515 | 1301 | 4E34 | 20020 | AND_MeetAndross |
| 0549 | 1353 | 4E35 | 20021 | AND_FalcoGreet |
| 0148 | 328 | 4E36 | 20022 | NWSH_MeetScales |
| 014A | 330 | 4E37 | 20023 | NWSH_BeatScales |
| 033A | 826 | 4E38 | 20024 | DR_WhatIWasLookingFor |
| 001D | 29 | 4E3D | 20029 | SH_StartStaffTutorial |
| 0020 | 32 | 4E40 | 20032 | SH_DoneStaffTutorial |
| 0388 | 904 | 4E41 | 20033 | |
| 0395 | 917 | 4E42 | 20034 | DR_SpellStoneIsInside |
| 015C | 348 | 4E43 | 20035 | DIM_HesGotSpellStone |
| 058B | 1419 | 4E44 | 20036 | LV_MaybeSpiritHere |
| 0283 | 643 | 4E45 | 20037 | CF_ThisMightHelp |
| 02AA | 682 | 4E46 | 20038 | CF_LoseRace |
| 0064 | 100 | 4E84 | 20100 | IM_HeyScaleFace |
| 0069 | 105 | 4E89 | 20105 | SB_OpeningScene |
| 0083 | 131 | 4E8B | 20107 | SB_MeetScales |
| 0490 | 1168 | 4E8C | 20108 | WM_KrystalLand |
| 008B | 139 | 4EAB | 20139 | NW_TrickyCrazy |
| 0598 | 1432 | 4EAC | 20140 | AND_YouLose |
| 059A | 1434 | 4EB6 | 20150 | WC_ThanksReturnStone |
| 00C9 | 201 | 4EE9 | 20201 | |
| 00CA | 202 | 4EEA | 20202 | |
| 00CB | 203 | 4EEB | 20203 | |
| 00D2 | 210 | 4EF2 | 20210 | SH_QueenNeedsShrooms |
| 00D5 | 213 | 4EF5 | 20213 | SH_QueenSaved |
| 00EA | 234 | 4F0A | 20234 | IM_HotSpring |
| 0115 | 277 | 4F35 | 20277 | |
| 0118 | 280 | 4F38 | 20280 | |
| 011E | 286 | 4F3E | 20286 | NW_MeetGarundaTe |
| 01FA | 506 | 501A | 20506 | SH_PepperFirstLanding |
| 01FC | 508 | 501C | 20508 | SH_MeetQueen |
| 0080 | 128 | 5078 | 20600 | SH_GetMedScarabBag |
| 0271 | 625 | 509B | 20635 | |
| 0493 | 1171 | 50B5 | 20661 | WM_DinoOpenDoorTest1 |
| 006D | 109 | 50D7 | 20695 | SB_YourAdventureBegins |
| 0180 | 384 | 50D8 | 20696 | WM_ReleaseSpirit1 |
| 059C | 1436 | 50DC | 20700 | DR_RescuedEarthWalker |
| 035F | 863 | 517F | 20863 | SH_WarpStoneIntro |
| 047F | 1151 | 529F | 21151 | SH_PickupStaff |
| 0492 | 1170 | 52B2 | 21170 | WM_DinoAfterTest1 |
| 049D | 1181 | 52BD | 21181 | SH_QueenExplainSpellStones |
| 0548 | 1352 | 5368 | 21352 | SH_NobodyBringsGifts |

## Debug Text

The debug text systems don't use the Gametext files at all. There's the more complex
`debugPrintf` system, used for most debug text, which supports the following control codes:

* 0x81 rr gg bb aa: Set color
* 0x82 yyyy xxxx: Set position
* 0x83: Leave fixed-width mode
* 0x84: Enter fixed-width mode
* 0x85 rr gg bb aa: Set background color?
* 0x86 aa bb: ?
* 0x87 aa bb: ?
* only 0x81 is used.

These are literal bytes, so write eg "\x81\xFF\x00\x00\xFFpotatoes" rather than UTF-8 encoding.

This uses texture IDs 1 (uppercase), 2 (lowercase), and 0x25D (digits and punctuation).

The second system, `debugPrintfxy`, is used for the crash handler and is much more basic,
supporting no control codes and using a built-in font.

## GAMETEXT.bin

The files `GAMETEXT.bin` and `GAMETEXT.tab` in the disc root are old, unused versions. Their
format isn't known, and they contain old dialogue not present in the final game.

## In this codebase

The whole "Gametext" subsystem lives in **`src/main/gametext.c`** and **`src/main/textrender.c`**,
backed by struct/typedefs in **`include/main/engine_shared.h`**. Nearly every wiki claim on this
page has a directly verifiable counterpart:

### Structs

| Wiki concept | Our symbol | Notes |
| --- | --- | --- |
| `characterStruct` (16 bytes: character/xpos/ypos/left/right/top/bottom/width/height/font/texture) | `TextGlyph` in `src/main/textrender.c:46-58` | Field-for-field match: `key`(u32)=`character`, `u`/`v`=`xpos`/`ypos`, `offsetX/advanceX/offsetY/advanceY`(s8x4)=`left/right/top/bottom`, `width/height`(u8x2), `lang/page`(u8x2)=`font/texture`. A second, less-decoded view of the same 12-byte-truncated shape exists as `GlyphEntry` in `include/main/engine_shared.h:451-454` (`u16 id; u8 pad[0xa];`) — `TextGlyph` is the fuller decode. |
| `gametextStruct` (identifier/numPhrases/window/alignH/alignV/language/phrases) | `GameTextDef` in `include/main/engine_shared.h:463-471` | `pad0[2]`=`identifier` (confirmed: `gameTextGet()` in `textrender.c:1262-1272` linear-scans `fonts->entries` in 12-byte (`+= 6` u16) strides comparing `*entry` — the struct's first u16 — against the caller's `textId`), `count`=`numPhrases`, `slotHint`=`window`, `f5`/`f6`=`alignH`/`alignV` (read in `gameTextFn_8001658c`, `gametext.c:809-858`; `f6` compared against the horizontal-justify `mode` constants and used to recompute a box coordinate from measured text bounds, `f5` toggles a box-height default), `pad7`=`language`, `strings`=`phrases`. A second occurrence of the same layout appears as `SubtitleTextEntry` in `textrender.c:3394-3400` (used for sequence subtitles). |
| `fontTextures[]` array / `TextFont`-level bookkeeping (`glyphs`, `entries`, counts, textures) | `TextFont` in `src/main/textrender.c:60-69` | `glyphs`=characterStruct array (count in `glyphCount`), `entries`=gametextStruct array (count in `entryCount`), `textures[3]`=loaded GX textures, `mode`=load-source selector, `timer`=fade timer. The public/shared version of this type (used by DLL code that only needs the glyph table) is `GameTextFont` in `include/main/engine_shared.h:455-462`. |
| GX texture format table (I4=00 … CMPR=0E) | `GXTexFmt` enum in `include/dolphin/gx/GXEnum.h:129-164` | Exact match: `GX_TF_I4=0`, `GX_TF_I8=1`, `GX_TF_IA4=2`, `GX_TF_IA8=3`, `GX_TF_RGB565=4`, `GX_TF_RGB5A3=5`, `GX_TF_RGBA8=6` ("RGBA32"), `GX_TF_C4=8`, `GX_TF_C8=9`, `GX_TF_C14X2=0xA`, `GX_TF_CMPR=0xE`. This is the standard Dolphin SDK enum, not something gametext-specific to add. |

### Control codes

`SpecialGlyph lbl_802C86F0[46]` in `src/main/gametext.c:1606` is exactly the wiki's control-code
table: `{key, paramCount}` pairs for `0xF8F2..0xF8FF` (in order: 2,0,1,1,1,1,0,0,0,0,0,0,0,4 params)
then `0xE000`(1), `0xE018`(3), `0xE020`(1) — a byte-for-byte match against the wiki's Param1-4
column counts. (The remaining 29 slots are `{0xF8FF,4}` filler/padding past the 17 real codes.)

`#define TEXT_CTRL_SCALE 0xf8f4` / `TEXT_CTRL_LANGUAGE 0xf8f7` / `TEXT_CTRL_ALIGN_LEFT 0xf8f8` /
`_RIGHT 0xf8f9` / `_CENTER 0xf8fa` / `_JUSTIFY 0xf8fb` / `TEXT_CTRL_COLOR 0xf8ff` are already
defined identically in both `src/main/gametext.c:5-6` and `src/main/textrender.c:18-24`. Note
`TEXT_CTRL_LANGUAGE` (0xF8F7) is the wiki's "Set Font" code — confirmed by its handler in
`textrender.c:632-633`/`995-996`, which stores `params[0]` into `glyphLang`, i.e. selects a font
ID, not a spoken language. The name is a slight misnomer relative to the wiki (see
"Ready-to-adopt" below).

`GameText_FindControlCodeArgs` (`gameTextGet` = `0x80018ED4` in `config/GSAE01/symbols.txt`,
defined at `src/main/textrender.c:3546`) is called with target `0xE018` ("Seq Time") from
`subtitleBuildLineTable` (`textrender.c:3405`, sequence subtitle timing) — `args[0]`/`args[1]`/
`args[2]` feed `s->times[i] = args[1] + args[0]*60 + args[2]/60`, consistent with the wiki's "Param
0 usually 0/1, Param 1 = seconds, Param 2 = unknown/fade" description.

### Font slots (0-3)

`gGameTextCharsets` (`GameTextStateElem gGameTextCharsets[0xA0 / sizeof(...)]`,
`src/main/textrender.c:1382`) is exactly the wiki's 4-slot table, and `gameTextLoadDir()`
(`textrender.c:1494-1554`) assigns slots by directory exactly as the wiki describes:
- `dirId == 3` (`sMapDirectoryNameTable[3]` = `Boot`) -> slot 2 ("error message font") — matches
  "Slot 2: directory Boot".
- `dirId == 0x1c` (`sMapDirectoryNameTable[0x1c]` = `Link`) -> slot 3 ("HUD font") — matches
  "Slot 3: directory Link".
- anything else -> slot 0 ("dialogue").
Slot 1 (cutscene/`Sequences`) is set via `gameTextSetCharset(1, ...)` around sequence playback
(e.g. `textrender.c:3433`, `3513`), matching "Slot 1: directory Sequences".

`TextGlyph.lang == 3` and `== 5` get bespoke rendering paths in `textrender.c:804-828` (scissor
adjustment for lang 3, centered/scaled placement for lang 5) — consistent with the wiki's Font 3
(Flags) and Font 5 (Character faces) being the two "colored icon" font IDs that need special
layout, as opposed to the plain monochrome text fonts 0/4.

### Sequence Lookup Table (0x802C8860) — exact match

`gTaskTextTable` (`include/main/engine_shared.h:314-318` for the `TaskTextEntry {u16 a; u16 b;
u16 key;}` type, data in `src/main/gametext.c:917`) is at **`.data:0x802C8860`** per
`config/GSAE01/symbols.txt:10330` — the literal address the wiki cites for the Sequence Lookup
Table. It has 208 entries (`size:0x4E0` / 6 bytes), and every entry's `b` field is `0x0029`,
matching the wiki's "every entry is 0x29 (Sequences)" (0x29 = 41 = the index of `"Sequences"` in
`sMapDirectoryNameTable[]`, `gametext.c:1655`). Spot-checked several rows against the wiki table
byte-for-byte, e.g.:
- `{ 0x0004, 0x0029, 0x00D1 }` = `a=Seq#=0004, key=ID#=00D1` -> wiki row `00D1|209|0004|4|Tricky_ThatsMyMa`.
- `{ 0x4E21, 0x0029, 0x0464 }` -> wiki row `0464|1124|4E21|20001|CF_FindAllChildren`.
- `{ 0x5368, 0x0029, 0x0548 }` (last entry) -> wiki row `0548|1352|5368|21352|SH_NobodyBringsGifts`.

All entries checked appear in the same declaration order as the wiki table, and the field
mapping is `a` = Seq# (text sequence id), `key` = ID# (object sequence id), `b` = constant 0x29
directory id.

`gameTextGetTaskText(int id, int* outA, int* outB)` (`src/main/gametext.c:70-88`) is the runtime
accessor: linear-scans `gTaskTextTable` for `e->key == id` (object sequence id) and returns
`outA = e->a` (text sequence id), `outB = e->b` (directory id, always 0x29). Called from
`gameTextLoadTaskText` (`src/main/textrender.c:1648`), whose body is the wiki's "if subtitles are
turned off, the file won't be loaded, with the exception of..." logic.

### Subtitle allow-list — exact match

`gGameTextTaskTextAllowList[12]` (`src/main/textrender.c:2340-2342`) is:

```C
s16 gGameTextTaskTextAllowList[12] = {
    0x69, 0x6d, 0x83, 0x490, 0x493, 0x492, 0x180, 0x47f, 0x1d, 0x20, 0x3c8, 0,
};
```

This is the wiki's exact 11-entry exception list, in the exact same order: `SB_OpeningScene`
(0x69), `SB_YourAdventureBegins` (0x6d), `SB_MeetScales` (0x83), `WM_KrystalLand` (0x490),
`WM_DinoOpenDoorTest1` (0x493), `WM_DinoAfterTest1` (0x492), `WM_ReleaseSpirit1` (0x180),
`SH_PickupStaff` (0x47f), `SH_StartStaffTutorial` (0x1d), `SH_DoneStaffTutorial` (0x20),
`MMP_BringSpiritToPalace` (0x3c8), 0-terminated. `gameTextLoadTaskText` (`textrender.c:1648-1682`)
checks `gSubtitlesEnabled` and, if off, only proceeds when `taskId` is in this list — exactly the
wiki's described behavior.

### ID ranges / hint texts (244+)

`saveGameGetCurHint()` in `src/main/dll/dll_0011_screens.c:56-60` is `gameTextGet(texts[5] + 0xf4)`
— the literal `+244` offset the wiki documents for hint texts tied to GameBits. The surrounding
file comment (`dll_0011_screens.c:1-16`) already describes the "TaskTextsNNN" directories and
per-task game-bit bookkeeping in the same terms as this wiki page. `include/main/gamebits.h`
holds the `GAMEBIT_*` enum referenced by "Each of these is referenced by a GameBit."

The 10000-19999 (pause menu/PDA descriptions) and 20000-29999 (sequence text) ID ranges are pure
data conventions — `gameTextGet(int textId)` (`src/main/textrender.c:1212`) is range-agnostic, so
there is no range-check code to point at; not found as a distinct code path.

### Paths / legacy files

- `sGameTextMapPathFormat[] = "gametext/%s/%s.bin"` — `src/main/textrender.c:929`.
- `sGameTextSequencePathFormat[] = "gametext/Sequences/%d_%s.bin"` — `src/main/textrender.c:2332`,
  matches the wiki's `4_English.bin` naming.
- `sResourceFileNameGametextBin[] = "GAMETEXT.bin"` and `sResourceFileNameGametextTab[] =
  "GAMETEXT.tab"` — `src/main/pi_dolphin.c:7970-7971`, the disc-root legacy files the wiki
  mentions as unused leftovers.
- `sMapDirectoryNameTable[74]` (`src/main/gametext.c:1655`) is the map/directory-name table used
  to resolve `dirId` to a path component (`"Sequences"`, `"Boot"`, `"Link"`, `"TaskTexts000"`..,
  etc.) — 74 entries, confirming directory ids used throughout this page (`0x29`=Sequences,
  `0x03`=Boot, `0x1c`=Link).

### Languages

`sLanguageNameTable[6]` (`src/main/gametext.c:1284-1291`) fixes the `LANGUAGE_xxx` order the wiki
references: `English=0, French=1, German=2, Italian=3, Japanese=4, Spanish=5` (Japanese is the only
entry with a different `sizeIdx`, 0 vs 4 for the rest — plausibly the monochrome-Japanese-font
special case). No `LANGUAGE_*` named constants exist yet in the codebase (see "Ready-to-adopt"
below).

### Not found

- No code was found that parses the raw `gametext/*.bin` file header fields (`numCharStructs`,
  `numTexts`, `strDataLen`, `numStrings`, `strOffset[]`, the `0xEE`-filled unknown block, or the
  per-file `fontTextures[]` block/stride formula) byte-by-byte — the DVD-load path
  (`gameTextOpenCallback_8001b3d0`, `src/main/textrender.c:1884`) only manages async load-slot
  state, not the parse itself. `gameTextLoadGraphicsFn_8001a918` (`textrender.c:2933`) loads the
  **console's built-in OS font** via `OSLoadFont`/`OSGetFontTexel` (a related but distinct
  mechanism from the file's own `fontTextures[]` block) — not a decode of the wiki's on-disc
  format.
- No `LANGUAGE_ENGLISH`/`LANGUAGE_FRENCH`/etc. named constants (only the implicit order in
  `sLanguageNameTable`).
- No font-ID named constants (`FONT_JAPANESE`, `FONT_ICON`, `FONT_FLAG`, `FONT_LATIN`,
  `FONT_FACE`) — only raw integer literals (`glyphLang`, `g->lang`).
- No PDA/pause-menu-specific gametext accessor distinct from the generic `gameTextGet`/
  `gameTextGetStr`/`gameTextGetPhrase` family.

## Ready-to-adopt code

These aren't struct changes (this doc doesn't edit headers) — just enums a maintainer could lift
into `include/main/engine_shared.h` or a new `gametext_ids.h`, derived from data already verified
above.

```C
/* Order fixed by sLanguageNameTable[] (src/main/gametext.c:1284). */
enum {
    LANGUAGE_ENGLISH  = 0,
    LANGUAGE_FRENCH   = 1,
    LANGUAGE_GERMAN   = 2,
    LANGUAGE_ITALIAN  = 3,
    LANGUAGE_JAPANESE = 4,
    LANGUAGE_SPANISH  = 5,
};

/* Per-glyph font id (TextGlyph.lang / GlyphEntry, characterStruct.font in the wiki). */
enum {
    GAMETEXT_FONT_JAPANESE = 0, /* + some Latin, monochrome */
    /* 1 does not exist */
    GAMETEXT_FONT_ICON     = 2, /* button icons */
    GAMETEXT_FONT_FLAG     = 3, /* language flags */
    GAMETEXT_FONT_LATIN    = 4, /* monochrome, non-Japanese text */
    GAMETEXT_FONT_FACE     = 5, /* character portraits */
};

/* Loaded font slot (gGameTextCharsets[0..3] index, src/main/textrender.c:1382). */
enum {
    GAMETEXT_SLOT_DIALOGUE = 0,
    GAMETEXT_SLOT_CUTSCENE = 1, /* Sequences */
    GAMETEXT_SLOT_ERROR    = 2, /* Boot */
    GAMETEXT_SLOT_HUD      = 3, /* Link */
};

/* Full in-string control-code table (Unicode PUA), from lbl_802C86F0 in
 * src/main/gametext.c + this wiki page; only TEXT_CTRL_SCALE/_LANGUAGE/_ALIGN_*/_COLOR
 * are currently named in src/main/textrender.c. */
#define TEXT_CTRL_SEQ_ID       0xe000 /* 1 param: sequence id (unused by the game) */
#define TEXT_CTRL_SEQ_TIME     0xe018 /* 3 params: ?, display-time seconds, ? */
#define TEXT_CTRL_HINT_ID      0xe020 /* 1 param: GameBit-linked hint id */
/* 0xf8f2/f3/f5/f6/fc/fd/fe: unused control codes seen in the retail table */
```

`TaskTextEntry` (`include/main/engine_shared.h:314-318`) and `gameTextGetTaskText`'s `outA`/`outB`
parameters (`src/main/gametext.c:70`) are good renaming candidates given the exact-match analysis
above: `a`/`outA` -> `textSeqId` (Seq#), `b`/`outB` -> `dirId` (always 0x29/Sequences), `key` ->
`objSeqId` (ID#). Likewise `GameTextDef.pad0` (`include/main/engine_shared.h:463`) is a real field,
not padding — the wiki's `identifier` (`u16`), consumed by `gameTextGet`'s linear scan.
