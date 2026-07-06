# Audio

> Source: [Rena Kunisaki's SFA wiki](https://github.com/RenaKunisaki/StarFoxAdventures/wiki/Audio). Reverse-engineering notes; not independently verified here.

## Audio files

All found under `/audio` on the disc (this page excludes `/streams` — see the wiki's `AudioStreams` page).

* `midi.wad`
* `starfox.h.bak` — old list of SFX IDs (doesn't match the final game)
* `starfoxm.poo`, `starfoxs.poo` — pool file
* `starfoxm.pro`, `starfoxs.pro` — project file
* `starfoxm.sam`, `starfoxs.sam` — sample file (the actual audio data)
* `starfoxm.sdi`, `starfoxs.sdi` — sample directory

Presumably `m` = music, `s` = sfx.

[axiodl/amuse](https://github.com/AxioDL/amuse) can parse this MusyX audio data (with some very heavy, arguably unnecessary, dependencies for what's just an audio decoder).

* `.proj` — project structure: what belongs to which group
* `.pool` — all data except samples
* `.sdir` — locations of samples needed by groups
* `.samp` — sample data

`/audio/data`:

| File | Size |
|---|---|
| `EmptyN.bin` (N = 0..7) | 256K each |
| `Music.bin` | 2.5K |
| `Sfx.bin` | 38K |
| `Streams.bin` | 20K |

## Sound effects

*(XXX where is this struct used? — unresolved in the source wiki)*

Low-level per-sound-sample entry:

| Offset | Type | Name | Description |
|---|---|---|---|
| 000000 | ushort | id | used to look up entry |
| 000002 | ushort | ? | flags? if FFFF, don't play |
| 000004 | byte | ? | |
| 000005 | byte | ? | |
| 000006 | byte | ? | |
| 000007 | byte | ? | |
| 000008 | u32 | offset | high byte: index into something 8 bytes; low 3 bytes: offset |
| 00000c | u16 | rate | higher = lower pitch |
| 00000e | u16 | pitch | higher = higher pitch - #samples? |
| 000010 | int | length | high byte = flags? |
| 000014 | u32 | repeatStart | repeat from this point... |
| 000018 | u32 | repeatEnd | ...to this one (if this isn't 0) |
| 00001c | u32 | variation | distorts in various random ways |

### SFX.bin entry

| Offset | Type | Name | Description |
|---|---|---|---|
| 000000 | u16 | id | |
| 000002 | u8 | baseVolume | |
| 000003 | u8 | volumeRand | volume = rand(baseVolume - volumeRand, baseVolume + volumeRand) |
| 000004 | u8 | basePan | 127 = center |
| 000005 | u8 | panRand | never used, works same as volumeRand |
| 000006 | u16 | ? | |
| 000008 | u16 | range | how far from source object to silence |
| 00000a | u16[6] | fxIds | actual sound to play (not same as `id`) (XXX are these the IDs in starfox.h.bak?) |
| 000016 | u8[6] | fxChance | chance to pick each sound |
| 00001c | ushort | randMax | sum of fxChance |
| 00001e | u8 | ? | maybe queue slot? high 4 bits are idx into `sfxTable_803db248` |
| 00001f | u8 | idxs | two 4-bit values: numIdxs (# items in fxIds), prevIdx (previously played index) |

Pseudocode to play a sound effect:

```
if id == 0xAB:
    //no idea what this is, just some kind of whoosh or creak.
    //it alternates between two different sounds every time it's played.
    //this check seems unnecessary though since the normal random
    //selection avoids repeats and so would have the same effect.
    entry->prevIdx ^= 1
    idx = entry->prevIdx
else:
    n = random between 1 and entry->randMax
    idx = the index of value n in entry->fxIds
        //eg if randVals = [10, 20, 30] and n = 22,
        //then idx = 2, since randVals[2] >= n

    //avoid playing the same sound twice in a row.
    //if we chose the same one as last time, use the next one.
    if entry->prevIdx == idx:
        idx += 1
        if idx > entry->numIdxs: idx = 0

entry->prevIdx = idx
outId = entry->randVals[idx]
if outId is 0, don't play

//compute the volume:
    if entry->volumeRand == 0:
        outVolume = entry->baseVolume
    else: outVolume = rand(
        entry->baseVolume - entry->volumeRand,
        entry->baseVolume + entry->volumeRand)

    //same calculation here, but result is cast to float.
    //panRand is 0 in every sound effect though
    if entry->panRand == 0:
        outPan = (float)entry->basePan
    else: outPan = rand(
        entry->basePan - entry->panRand,
        entry->basePan + entry->panRand)

u8 sfxTable_803db248[8] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0};

outField6  = (float)unk06
outRange   = (float)range
outTable1E = sfxTable_803db248[unk1E >> 4]
out1ELow   = unk1E & 1
out1EHigh  = (unk1E >> 3) & 1
```

### Sound Effect IDs

(names made up by the wiki author)

| ID | Name |
|---|---|
| 001D | FoxClimbUp |
| 001F | KrystalHurt |
| 0024 | FoxHurt |
| 0025 | FoxClimbUp2 |
| 0026 | FoxFallScream |
| 0027 | FoxLandOof |
| 0029 | FoxGrabLedge |
| 002E | FoxRoll |
| 002F | ClimbOutOfWater |
| 0049 | RecoverHealth |
| 0058 | GenericItemPickup |
| 0069 | ToggleDisguise |
| 006F | Clang |
| 0098 | MenuOpen |
| 009E | ElectricCrackle |
| 00BA | SplashBA |
| 00C0 | StaffTakeOut |
| 00C1 | StaffPutAway |
| 00C2 | SmackC2 |
| 00C3 | SmackC3 |
| 00E7 | RobotTalk |
| 00E8 | RobotHover |
| 00E9 | RobotZap |
| 00F3 | PipF3 |
| 00F4 | DootF4 |
| 00F5 | MenuOpenF5 |
| 00F7 | CMenuEquip |
| 00FB | Ding |
| 00FC | TitleScreenZip |
| 00FD | Squak |
| 00FF | TitleScreenOpenMenu |
| 0100 | TitleScreenCloseMenu |
| 010A | SpellCastFailed |
| 013D | TrickyDigging |
| 016C | BallBounce |
| 017B | Thud17B |
| 017C | Thud17C |
| 020E | FoxFallScream1 |
| 020F | FoxFallScream2 |
| 0285 | Drip |
| 0286 | CameraTurnBehindPlayer |
| 0287 | Drop |
| 0288 | Whoosh288 |
| 0289 | Whoosh289 |
| 028B | Whoosh28B |
| 028C | TickTickTick |
| 028D | CymbalCrash |
| 029D | TrickyFinishFlame |
| 02CB | KrystalGrabLedge |
| 02D0 | KrystalFallScream |
| 034D | Tricky_WaitUpFox |
| 034E | Tricky_WaitForMe |
| 034F | Tricky_Hey |
| 0350 | Tricky_GetOff |
| 0351 | Tricky_LookAtThis |
| 0352 | Tricky_ImHungry |
| 0353 | Tricky_Yawn2 |
| 0354 | Tricky_Yawn |
| 0355 | Tricky_LetsPlay |
| 0356 | Tricky_Cool |
| 0357 | Tricky_Sniff |
| 0358 | Tricky_BadGuy |
| 0359 | Tricky_Food |
| 035A | Tricky_TheresSomethingNear |
| 035B | Tricky_GetMFox |
| 035C | Tricky_Yeah |
| 035D | Tricky_ImNotDoingIt |
| 035E | Tricky_Hello |
| 035F | Tricky_HiFella |
| 0360 | Tricky_Dumdedum |
| 0361 | Tricky_Laugh |
| 0362 | Trick_Chewing |
| 0363 | Tricky_MmmmTasty |
| 0364 | Tricky_ImStuffed |
| 0365 | Tricky_WhereAreWeGoing |
| 0378 | FoxAttack378 |
| 037B | TitleScreenChangePage |
| 037C | CMenuClose |
| 0382 | IceSpell |
| 038D | WarningBeep |
| 0394 | Burning |
| 0395 | PutOutFlame |
| 0397 | TextPip |
| 0398 | KrystalClimbUp |
| 0399 | KrystalLandOof |
| 03CD | KrystalRoll1 |
| 03CE | KrystalRoll2 |
| 03D8 | StaticyRadarBeep |
| 03DC | TrickySpewingFire |
| 03E5 | PauseMenuOpen |
| 03E8 | HagabonWhir |
| 03EB | ElectronicChime3EB |
| 03EC | ElectronicChime3EC |
| 03ED | MapChangeMode |
| 03EE | MenuOpen3EE |
| 03EF | MenuClose3EF |
| 03F0 | MapZoom |
| 03F1 | Pip3F1 |
| 03F2 | PauseMenuClose |
| 03F4 | RobotActivate |
| 03F7 | TrickyCommandDecoy |
| 03F8 | TrickyCommandFind |
| 03F9 | TrickyCommandFlame |
| 03FA | TrickyCommandGoGetIt |
| 03FB | TrickyCommandWhistle |
| 03FC | TrickyCommandStay |
| 03FF | ZipUp |
| 0400 | ZipDown |
| 0401 | MenuSlide |
| 0402 | Chime |
| 0405 | Blip |
| 0408 | CMenuOpen |
| 0418 | TitleScreenSelect |
| 0419 | TitleScreenCancel |
| 041A | TitleScreenBeep |
| 041B | ZipUp41B |
| 041C | Zap |
| 0420 | WarpIn |
| 0427 | RollInWater |
| 042B | Splash42B |
| 0467 | Warping |
| 0470 | EvilLaugh |
| 0471 | Woosh471 |
| 0472 | Woosh472 |
| 047B | GlassSmash |
| 04A2 | Teleport |

## In this codebase

Verified by reading `src/main/audio.c`, `include/main/engine_shared.h`, `include/main/audio/*.h`, and `config/GSAE01/symbols.txt`.

**File table (audioInit / audioLoadTriggerData).** `audioInit()` and `audioLoadTriggerData()` in
`src/main/audio.c` load exactly the files this page lists, confirming the wiki's directory
layout byte-for-byte from the retail string data (all packed into one literal blob,
`sSampleBufferSLoadedCallbackLoadError` a.k.a. `base`, and indexed with `base + 0x1a4`-style
offsets — that packing is itself the MWCC string-pooling behavior the retail binary produces,
not a decomp artifact):
  - `/audio/data/Music.bin`, `/audio/data/Sfx.bin`, `/audio/data/Streams.bin` — loaded by
    `audioLoadTriggerData()` into `gMusicTriggersData` / `gSfxTriggersData` / `gStreamsData`.
  - `/audio/starfoxm.poo/.pro/.sdi/.sam` and `/audio/starfoxs.poo/.pro/.sdi/.sam` — loaded by
    `audioInit()` into the `gAudioStarfoxM*`/`gAudioStarfoxS*` handles and pushed via
    `sndPushGroup()`.
  - `/audio/midi.wad` — path constant `sMidiWadPath` in `src/main/audio.c`, loaded by
    `musicInitMidiWad()`.

**SFX.bin entry struct → `SfxTriggerFull`.** `include/main/engine_shared.h` defines
`SfxTriggerFull`, and its field offsets match the wiki's "SFX.bin entry" table exactly
(verified byte offset by byte offset), confirmed by `gSfxTriggersCount = (u32)info >> 5` in
`audioLoadTriggerData()` — i.e. each entry is 32 (0x20) bytes, exactly `sizeof(SfxTriggerFull)`:

  | Wiki offset/name | This repo |
  |---|---|
  | 0x00 `id` | `id` (u16) — binary-search key, see `Sfx_FindTrigger` below |
  | 0x02 `baseVolume` | `volBase` (u8) |
  | 0x03 `volumeRand` | `volRand` (u8) |
  | 0x04 `basePan` | `pitchBase` (u8) — **naming conflict, see below** |
  | 0x05 `panRand` | `pitchRand` (u8) — **naming conflict, see below** |
  | 0x06 `?` | `field_6` (u16) — **resolved: near distance**, see below |
  | 0x08 `range` | `field_8` (u16) — **resolved: far distance**, see below |
  | 0x0a `fxIds[6]` | `sfxIds[6]` (u16[6]) |
  | 0x16 `fxChance[6]` | `weights[6]` (u8[6]) |
  | 0x1c `randMax` | `selectRange` (u16) |
  | 0x1e `?` (queue slot / table idx) | `e_tableIdx:4, e_bit3:1, e_pad:2, e_bit0:1` bitfield |
  | 0x1f `idxs` (numIdxs, prevIdx) | `f_count:4, f_curIdx:4` bitfield |

  Two things this repo's decomp resolves beyond the wiki's "?" marks:
  - **Offsets 0x06/0x08 are a near/far distance pair, not one `range` value.** In
    `Sfx_ReadTriggerParams` (`src/main/audio.c`), `trigger->field_6` and `trigger->field_8` are
    each cast to float and threaded through `Sfx_PlayFromObjectEx` as `nearDist`/`farDist`,
    which `Sfx_UpdateObjectChannel3D` uses for volume falloff and cull distance. So the wiki's
    "range" (offset 8) is specifically the *far* cutoff; offset 6 (wiki's "?") is the *near*
    cutoff where falloff starts.
  - **`gSfxTriggerExtraTable` is exactly the wiki's `sfxTable_803db248[8]`.**
    `config/GSAE01/symbols.txt` places `gSfxTriggerExtraTable` at `.sdata:0x803DB248, size:0x8`
    — same address, same size as the wiki's table. It's declared only as a scalar
    (`extern u8 gSfxTriggerExtraTable;`) in `include/main/engine_shared.h` and indexed as
    `(&gSfxTriggerExtraTable)[trigger->e_tableIdx]` in `Sfx_ReadTriggerParams` — the array bound
    isn't expressed in the type. See "Ready-to-adopt code" below.

  Possible discrepancy worth checking: the wiki labels offset 0x04/0x05 `basePan`/`panRand`
  ("127 = center"), this repo names them `pitchBase`/`pitchRand`. The value computed from them
  (`Sfx_ReadTriggerParams`'s `outF6`) is threaded through `Sfx_PlayFromObjectEx` as a `pitch`
  local and passed into `Sfx_AllocObjectChannel`'s `double pitch` parameter — which that
  function then never reads (only `a`/`b`/`c`/`d` reach `sndFXStartEx`). Since the field is a
  dead value by that point either way, this doesn't confirm either name; but "127 = center" reads
  much more like a pan center-point than anything pitch-related, so `pitchBase`/`pitchRand` may
  be a misnomer left over from an earlier guess. Not changed here (out of scope for this doc).

**Sound-effect selection pseudocode → `Sfx_ReadTriggerParams`.** The wiki's whole "Pseudocode to
play a sound effect" block matches `Sfx_ReadTriggerParams` in `src/main/audio.c` near-verbatim,
including the `id == 0xAB` special case:
  ```c
  if (trigger->id == 0xab) {
      trigger->f_curIdx = trigger->f_curIdx == 0 ? 1 : 0;
      idx = trigger->f_curIdx;
  } else {
      selector = randomGetRange(1, trigger->selectRange);   // wiki: n = random(1, randMax)
      idx = 0;
      while (selector > trigger->weights[idx]) { selector -= trigger->weights[idx]; idx++; }
      if (trigger->f_curIdx == idx) { idx++; if (idx >= trigger->f_count) idx = 0; }
  }
  ```
  `Sfx_FindTrigger(u16 id)` (`src/main/audio.c`) is the "look up entry" binary search over
  `gSfxTriggersData`/`gSfxTriggersCount`, with a small direct-mapped cache
  (`gSfxTriggerLookupCache[key & 0xf]`, type `SfxTriggerCacheEntry`) not mentioned in the wiki.

**Two different "id" spaces, both present in this repo, and the wiki's open question is
answered.** The wiki asks "(XXX are these the IDs in starfox.h.bak?)" about the `fxIds[6]`
values. Based on this repo:
  - `include/main/audio/sfx_trigger_ids.h` — `SFXTRIG_*`, the **trigger id** space: values
    passed to `Sfx_PlayFromObject()`/`Sfx_Find Trigger()`, i.e. the same key space as the
    `SfxTriggerFull.id` field / the wiki's "Sound Effect IDs" table (values up to `0x4c2` and
    the sentinel `0xffff`, matching the wiki's "if FFFF, don't play" flags note on the
    low-level struct).
  - `include/main/audio/sfx_ids.h` — `SFX*`, the **raw MusyX sample id** space: 828 entries
    (index 0..827), generated "from `orig/GSAE01/files/audio/starfox.h.bak`" per its own header
    comment — literally the file the wiki calls out by name. `trigger->sfxIds[idx]` (resolved
    per-play by `Sfx_ReadTriggerParams`, named `outSfxId`/`*outSfxId`) is exactly this space:
    it's what ultimately reaches `sndFXStartEx()`. So yes — the wiki's guess was right, the
    `fxIds[6]` entries are `starfox.h.bak`/`sfx_ids.h` ids, distinct from the trigger's own `id`.

  Cross-checking specific hex values: the wiki's "Sound Effect IDs" table above is in the
  *trigger* id space (values exceed 827, so they can't be raw MusyX ids), the same space as
  `sfx_trigger_ids.h`. Spot-checking overlapping values (e.g. `0x1D`, `0x24`, `0x98`, `0x2CB`)
  against `sfx_trigger_ids.h`'s comments shows disagreement for most entries — the two lists
  were derived independently (this repo's from call-site literals actually found in decompiled
  source; the wiki's from in-game observation) and should **not** be assumed to name the same
  trigger. A few do plausibly line up (Krystal-prefixed (`SFXkr_*`) targets around `0x2D0`,
  `0x398`, `0x399`; `0x9E` → `SFXTRIG_forcecryslp11` plays `SFXen_forcecryslp11`, a force-crystal
  loop, plausibly the wiki's "ElectricCrackle"). Reconciling the rest would need call-site
  content review, not assumed by this doc.

**`SfxObjectChannel`** (`include/main/engine_shared.h`) is the live-voice bookkeeping struct behind
`gSfxObjectChannels[]` (`src/main/audio.c`, sized `SFX_OBJECT_CHANNEL_COUNT`) — one entry per
currently-playing positional SFX, holding `handle`, `x`/`y`/`z`, `nearDistance`/`farDistance`
(copied from the resolved trigger's `field_6`/`field_8`), `volume`, `sfxId`, `channelMask`, and
an `age` counter. Not described in the wiki; it's downstream of the trigger-lookup machinery
the wiki does describe.

**DLL 0x0133 (`sfxplayer`)** (`include/main/dll/sfxplayer.h`, `src/main/dll/dll_0133_sfxplayer.c`)
is a separate, higher-level concept: a placeable game object that drives ambient/triggered SFX
playback with its own `SfxplayerState`/`SfxplayerStateFlags`. It calls into the same
`Sfx_PlayFromObject`-family API this page describes, but the wiki doesn't cover it — it's not
part of the SFX.bin data format itself.

**Not found in this codebase / not mapped:**
- The low-level "Sound effect" struct at the top of the wiki page (offset/rate/pitch/length/
  repeatStart/repeatEnd/variation) — this looks like a per-MusyX-sample header inside the
  `.samp`/`.sdir` data (i.e. the amuse-parseable pool format), not something reflected as a
  named C struct anywhere in `src/main/audio/*`; the DSP-facing code (`hw_sample.c`,
  `vsample_alloc.c`, etc.) works through raw byte-offset pointer arithmetic into `dspVoice`
  rather than a struct with these field names. If it exists as a distinct decompiled struct,
  it wasn't found by this pass.
- `orig/GSAE01/files/audio/starfox.h.bak` itself isn't checked into this repo (assets are
  gitignored, `orig/*/*` in `.gitignore`) — only its already-recovered `#define` output
  (`sfx_ids.h`) is present.
- No `.poo`/`.pro`/`.sam`/`.sdi`/`.wad` asset files are present in this checkout (data files,
  not source).

## Ready-to-adopt code

`gSfxTriggerExtraTable` is declared as a bare scalar even though every use of it
(`(&gSfxTriggerExtraTable)[trigger->e_tableIdx]` in `Sfx_ReadTriggerParams`) indexes it, and
`config/GSAE01/symbols.txt` confirms the backing symbol is 8 bytes at `0x803DB248` — matching
the wiki's `sfxTable_803db248[8]` address and size exactly. Turning it into a properly-sized
array would make the indexing self-documenting instead of relying on pointer arithmetic off a
scalar extern:

```c
/* include/main/engine_shared.h — currently:
 *   extern u8 gSfxTriggerExtraTable;
 * Confirmed 8 bytes at 0x803DB248 (config/GSAE01/symbols.txt). Contents below are the wiki's
 * claimed values (a bitmask table, powers of two 0x01..0x40 then 0) — NOT independently
 * confirmed against this ROM by this pass; verify with a hex dump of 0x803DB248 before
 * committing the literal bytes, only the size/shape is confirmed here. */
extern u8 gSfxTriggerExtraTable[8]; /* candidate content, per wiki, UNVERIFIED:
                                        { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0 } */
```
