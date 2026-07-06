# Tricky

> Source: [Rena Kunisaki's SFA wiki](https://github.com/RenaKunisaki/StarFoxAdventures/wiki/Tricky). Reverse-engineering notes; not independently verified here.

Tricky is one of the game's most complex subsystems, with lots of subtleties, easter eggs, and
unused functions.

## Attacking the player

If you smack Tricky too often, he'll spew fire on you. This is abused in speedruns because it
doesn't cost any food and can be done anywhere for death abuse. The exact requirements are:

- He must be in his "idle" or "pissed off" state (not focused on a baddie/ball, not
  digging/attacking, etc). In other states he doesn't notice he's being hit.
- Only hits from Fox or an object Fox holds count — in practice, only the staff. Thrown objects,
  Fire Blaster, Ice Blaster, Ground Quake etc. don't trigger it (he fails to attribute them to the
  player). He also doesn't care if Krystal hits him, but she never gets the chance.
- A `hitByPlayerTimer` is set to 180 frames (3s) on the first qualifying hit, with a "hey!" shout —
  **phase one**.
- Subsequent hits before the timer expires add 600 frames, trigger a "get off!" shout, and put him
  in the "pissed off" state (he stops obeying commands) — **phase two**.
- At 3000, the timer is halved and he tries to attack — requires the Flame command learned and not
  being in water, otherwise he just says "get off!" again. He needs no energy and consumes none —
  **phase three**. Since the timer is halved (~1500 frames / 25s), further hits in that window
  re-trigger phase three (halving again after adding 600).
- Net effect: ~6 rapid hits to trigger an attack; ~7 in practice given staff swing time.
- Feeding him resets the timer to 0 and the state to Idle, even if not hungry. Other things (e.g.
  using Flame on a baddie) might also reset it, but since he's disobedient by then it may be
  unreachable.

## Unused functions

### Decoy

Would have had Tricky distract a baddie so the player could sneak past — likely the original plan
for `BribeClaw` before it became a paywall. Gecko code `0231B57C 00000002` replaces the Call Tricky
command's action with this one; it doesn't do anything but plays an unused voice clip. Has an
unused Communicator description: "Decoy Move" / "With this command you can use Tricky as a decoy
while you sneak around without getting noticed!"

### Guard

Possibly the real implementation of Decoy, or an unrelated command. Gecko code `0431D340
8013FFB8` replaces his "growl at baddie" function with this one. In this state he gets in the
enemy's way and tries to push them around; debug text suggests he'd also Flame them unprompted.

### Baddie Alert

Not truly unused, but changed: originally a shop purchase that made the staff glow red near
enemies, replaced with Tricky running up and growling instead. The shop name/description strings
are still present: "Baddie Alert" / "This is the BAD GUY ALERT." / "Your Staff will glow red..." /
"...whenever there is a baddie nearby."

### Increased Food Capacity

The save file stores Tricky's current and maximum energy. In normal play the maximum is always 20
(5 mushrooms). Raising it works functionally but doesn't affect the HUD.

### Kyte

Krystal was originally meant to have a sidekick named Kyte, doing tasks similar to Tricky's. The
only apparent remnant is his model — the caged bird on Scales' galleon, internally named
`CagedKyte`. Evidence suggests Krystal (not a conveniently-passing queen) was meant to visit
LightFoot Village and be the one tied up, implying Kyte was originally meant to free her there.

## Playing

Tricky's Ball can be bought at the shop and thrown to play with him; not required to finish the
game. Throwing it somewhere it gets stuck can print a "HIT OVERFLOW" message with no other visible
effect. For every 10 successful retrieves (up to 239 total) he changes color; colors are said to
affect things like how often he speaks (unresearched by the wiki). While retrieving the ball he
won't obey commands, and while staring at a just-thrown ball he won't notice being hit. If thrown
somewhere unusable, or if it's disabled mid-flight (e.g. a boss waking up), it just disappears.

## Exploits and bugs

There aren't many known Tricky exploits besides smacking him to trigger death-abuse escapes after
a sequence break. He can push the player in various states (even off ledges), which might be
useful.

### Mammoth Dismount

Equip food to the Y button, ride the SnowHorn in DarkIce Mines, clip into a wall so Tricky is
close enough to feed, then feed him — Fox dismounts but keeps controlling him while still
"mounted." This is potentially very powerful:

1. The "stop Fox from moving" out-of-bounds check is skipped because the mounted-object field
   isn't cleared, so swimming while glitched can slowly reach almost any connected map.
2. Leaving the map unloads the SnowHorn without clearing the mounted-object pointer — a
   use-after-free. With precision, a staff fireball can allocate into the freed memory and hit
   triggers as if Fox were still riding it.
3. Pressing A while the SnowHorn is still loaded warps Fox back to it, potentially firing any
   trigger crossed en route, however far away.

The bike in Ice Mountain has a similar dismount glitch (unrelated to Tricky).

### Death Crash

Dying or getting stuck out of bounds with food on Y near Tricky, then spamming Y, queues a "feed
Tricky" action per press. When the queue fills, an error message prints, but the print code is
bugged — it tries to print both objects' names when there's only one, causing a null pointer
dereference. Reviving with a full-but-not-overfull queue just clears it without feeding him. Not
exploitable; patched in Amethyst Edition.

### Weird Head Movement

During the first scene explaining how to feed Tricky, his head/tail can move to strange angles —
subtle and easy to miss. Caused by a typo in a trig constant used only in that scene: `325767`
instead of `32767`. No practical effect.

## In this codebase

Everything below was checked against this repo's source, headers, and `config/GSAE01/symbols.txt`
— not re-derived from the wiki.

### Core Tricky object and files

- The main Tricky companion is DLL `0x00C4` -> `src/main/dll/dll_00C4_tricky.c` /
  `include/main/dll/dll_00C4_tricky.h`, extra-state struct `TrickyState` ->
  `include/main/dll/tricky_state.h` (`Tricky_getExtraSize` returns `0x83C`; struct is `0x840`).
  Command/substate handlers split across `src/main/dll/tricky_substates.c`,
  `src/main/dll/tricky_flameguard.c`, `src/main/dll/tricky_rollroute.c`, and
  `src/main/dll/trickyfollow.c` / `include/main/dll/baddie/trickyfollow.h`.
- `src/main/dll/tricky.h`/`.c` and `src/main/dll/dll_8011d918.c` are a **naming collision**, not
  the Tricky character — that TU is pause-menu/HUD drawing code (`pauseMenuTextDrawFn`,
  `hudDrawAirMeter`, etc.) that happens to live in a file called `tricky.c`/`tricky.h`. Don't
  confuse it with `dll_00C4_tricky.c`.
- Map-specific Tricky variants (cutscene/placement stand-ins, not the main companion): DIM
  (`src/main/dll/DIM/dll_019E_dim_tricky.c`, `dll_01D0_dimtricky.c`), NW
  (`src/main/dll/NW/dll_01A2_nwtricky.c`), SH (`src/main/dll/SH/dll_01A6_shtricky.c`).
  `TrickyCurve` (`include/main/dll/TrickyCurve.h`, `include/main/dll/trickycurve_state.h`) is a
  related but separate rom-curve-driven object type.

### Attacking the player

**Not conclusively located.** `Tricky_hitDetect` (`dll_00C4_tricky.c`) is a same-named but
unrelated function — it tracks nearby floor heights for foot placement, not player hits.
`TrickyState` does carry `lastContactObj` / `contactTimer` / `hitCooldown` fields at
`0x360`/`0x364`/`0x370` (`tricky_state.h`), and `dll_00C4_tricky.c`'s `baddie_updateWhileFrozen`
dispatches Tricky's own `seqId`s (`0x11`, `0x13a`, `0x5b7`-`0x5b9`, `0x5e1`, `0x7a6`) to
`sidekickToy_handleHitMessage` (`src/main/dll/newseqobj.c`) for hit-reaction/anim handling, but
that function implements a generic curve-toy "hit counter" reaction, not the specific
180/600/3000-frame escalation or the "hey!"/"get off!" voice lines described by the wiki. The
`TRICKY_VOICE(obj, st, sfx, vol)` macro in `dll_00C4_tricky.c` (guards playback by
`statusFlags` bit 6 and anim-move range, then calls `objAudioFn_800393f8`) is almost certainly the
mechanism used for those shouts, but the specific vox ids (raw hex like `0x364`/`0x363` at the
call sites) aren't mapped to English line text in this repo, so which one is "hey!" vs "get off!"
is unconfirmed.

### Unused functions

- **Guard**: `trickyGuard = .text:0x8013FFB8` in `config/GSAE01/symbols.txt` is an **exact address
  match** to the wiki's Gecko code (`0431D340 8013FFB8`, a 32-bit write of that function pointer).
  `trickyGuard`'s body lives in `src/main/dll/tricky_flameguard.c` (defines `TrickyRuntime` with a
  `guardState`, `guardPoint`, `guardTarget`, `guardTimer`, and `guardHelpers[7]` — it makes Tricky
  hold a point and spawn up to 7 flameblast helpers, def id `0x4F0`). Contrary to the wiki calling
  this purely "unused," `trickyGuard` **is** wired up in retail — just via map-placed objects, not
  the player-selectable command menu: DLL `0x0101` (`src/main/dll/dll_0101_trickyguard.c`,
  `TrickyGuard_init`/`_update`) and DLL `0x0120`
  (`src/main/dll/dll_0120_trickyguardspot.c`, `TrickyGuardSpot_*`) are placeable "guard volume"
  objects that call the live Tricky object's vtable slot `TRICKY_VTBL_GUARD` (`+0x28` byte offset,
  index `0x0A`) to issue this behavior when the player enters range. The "growl at baddie" handler
  the wiki says this Gecko code *replaces* is `trickyGrowl` (`src/main/dll/tumbleweedbush.c:61`,
  symbol `trickyGrowl = .text:0x8013DC88`) — a four-step substate machine per that file's header
  comment.
- **Decoy**: the wiki's Gecko write target `0x8031B57C` falls inside `gCMenuTrickyAbilities`
  (`.data:0x8031B578`, size `0x60` — see `include/main/dll/cmenu_item_table.h`), specifically at
  byte offset 4 of the first `CMenuItemDef` entry (the `activeGameBit` field of the "Call Tricky"
  row). This address coincidence is suggestive but **not verified** as the actual "Call Tricky
  command's action" dispatch the wiki describes — the real per-command handler table (indexed by
  `TrickyState.unk08` via `Tricky_update`'s `handlerBase`) is anchored at `lbl_8031D2E8`, a
  different, only-partially-typed data blob (see `dll_00C4_tricky.c` `Tricky_update`,
  `TrickyHandlerTable`). No unused "Decoy" symbol/function was found by name.
- **Baddie Alert**: already covered in `docs/wiki/Shop.md` — shop row `0x18` is literally named
  "Bad Guy Alert (unused)", gated by `aval` GameBit `0x0096` = `GAMEBIT_Always0`
  (`include/main/gamebits.h:335`, commented *"used for never-available (unused) shop items"*),
  i.e. permanently unavailable by construction. No re-derivation needed here.
- **Increased Food Capacity**: `SaveGame_getTrickyEnergy` (`.text:0x800E9B70`,
  `src/main/dll/dll_0017_savegame.c:1027`) returns `gSaveGameData + 0x18`. `Tricky_init`
  (`dll_00C4_tricky.c:1583`) stores this pointer as `TrickyState.progressPtr` via
  `(*gMapEventInterface)->getTrickyEnergy()` (`include/main/mapEventTypes.h:34`, vtable offset
  `0x94`). Byte `[0]` of that record is consumed as an energy counter elsewhere (decremented by
  Flame/attack use in `src/main/dll/tumbleweedbush.c:144`, `src/main/dll/animobjd2.c:432`, read in
  `src/main/dll/weapone6.c:318`); byte `[2]` drives `modelVariant` (below). **Not found**: a
  distinct "maximum energy" field — only one energy-like byte and the ball-progress byte are
  identified in this pass, so the wiki's "current and maximum, max always 20" claim isn't yet
  pinned to two separate save bytes here. `GAMEBIT_ITEM_TrickyFood_Count = 0xC1` (table 2, size 4,
  `include/main/gamebits.h`) is a **different**, unrelated counter — the player's carried GrubTub
  Fungus inventory, not Tricky's own energy meter.
- **Kyte**: confirmed and better-documented in our own code than the wiki:
  - `src/main/dll/dll_0266_kytesmum.c` — DLL `0x266`, object type `0x43`, "Kyte's mum" NPC (per the
    file's own header comment), supporting the wiki's inference of a Kyte backstory beyond just
    the caged bird.
  - `CagedKyte` on Scales' galleon: `src/main/dll/SB/dll_01F2_sbcagekyte.c` (`SB_CageKyte`, DLL
    `0x1F2`, "Kyte, the captive baby Cloudrunner held in the deck cage... during the ShipBattle
    prologue") and `src/main/dll/SB/dll_01F0_sbkytecage.c` (`SB_KyteCage`, DLL `0x1F0`, the cage
    object itself, `include/main/dll/sbkytecagestate_struct.h` -> `SBKyteCageState`). Matches the
    wiki's claim almost verbatim, including that "Kyte is never actually freed — talking just
    opens the deck door."

### Playing (Tricky's Ball)

- Ball object: DLL `0x00F5` -> `src/main/dll/dll_00F5_sidekickball.c` /
  `include/main/dll/dll_00F5_sidekickball.h`, `SidekickBall_init`/`_update`, mode machine
  `SidekickBallMode` (`IDLE` -> `trickyBallFn_801793b8`, `THROWN`/`MOVING` ->
  `trickyBallMove`, `FADING`). Per the file's own header comment, the ball self-frees if the
  player or Tricky is missing/dead, or `GAMEBIT_NoBallsAllowed = 0xD00` ("Disables/despawns
  Tricky's ball", `include/main/gamebits.h`) is set — this is the "if it suddenly becomes disabled
  (e.g. boss awake) it will just disappear" behavior from the wiki.
- Color-per-10-retrieves: `Tricky_init` (`dll_00C4_tricky.c:1592`) computes
  `modelVariant = progressPtr[2] / 10` and stores it in `TrickyState.modelVariant`
  (`tricky_state.h`, already commented `/* progress/10; indexes model bank color */` before this
  pass), then writes it into the active model's color-bank byte. This is an exact structural match
  to "every 10 successful retrieves (up to 239) changes color" — `239 / 10 = 23`, i.e. `0..23`
  model-bank variants, consistent with a `u8` progress counter the game caps below `240`.
  Whether "colors change how often he talks" is separately implemented was not chased further in
  this pass.
- `GAMEBIT_ITEM_TrickyBall_Bought = 0x25`, `GAMEBIT_ITEM_TrickyBall_Usable = 0x3F8` (set after
  first throw, allows multiple balls), all in `include/main/gamebits.h`.

### Exploits and bugs

- **Mammoth Dismount (DarkIce Mines SnowHorn)**: the rideable SnowHorn is DLL `0x256` ->
  `src/main/dll/DIM/dll_0256_dimsnowhorn1.c` (`DIMSnowHorn1State.mountMode`: `0` = unmounted,
  `2` = riding; local `#define GAMEBIT_SNOWHORN_RIDING 0x3e3`, which matches
  `GAMEBIT_NW_SnowHorn03E3 = 0x3E3` in `include/main/gamebits.h:547`, commented "related to riding
  SnowHorn" despite its `NW`-prefixed name). The player-side "mounted object" pointer the wiki says isn't
  cleared on unload is **plausibly** `PlayerState.groundObject`
  (`include/main/dll/player_state.h:125`, "object the player stands on/rides; transform parent for
  relative pos, set from collision hit") — used extensively in `src/main/dll/player.c` — but this
  mapping is **not independently confirmed** by tracing the specific out-of-bounds freeze check the
  wiki describes.
- The similar Ice Mountain bike dismount: DLL for the bike is `src/main/dll/dll_0255_snowbike.c`;
  `GAMEBIT_IM_OnBike = 0xC8` (`include/main/gamebits.h`).
- **Death Crash**: **found, exact match.** `sideCommandEnable` (`dll_00C4_tricky.c:358`) is a
  generic command-enqueue function taking a `targetObj` — the shape "Feed to Tricky" needs
  (target = the food item), though the specific caller that wires the Y-button food item to this
  function was not traced in this pass: `if (((TrickyState*)state)->unk798 == 10) {
  trickyReportError(sSidekickCommandDebugTextBlock); return; }`. The embedded debug string it reports (`dll_00C4_tricky.c:3107`,
  `sSidekickCommandDebugTextBlock`, decoded from its raw byte initializer) reads literally
  `"sideCommandEnable warning: need to increase MAX_COMM_PRESENT\n"` — i.e. the retail devs' own
  name for the queue-full condition the wiki describes, with a hard cap of `10` queued commands.
  The queue itself is the array at `state+0x748` (`targetObj`, 4B) /`+0x74c` (`commandKind`, 1B) /
  `+0x74d` (`commandType`, 1B) /`+0x74e` (a status byte), stride `8`, counted by `unk798` — this
  whole range is still opaque padding in `tricky_state.h` (`pad744[0x798-0x744]`). One wrinkle:
  `trickyReportError`/`trickyDebugPrint` (`dll_00C4_tricky.c:~2933`) are both **empty stub
  functions** in this build (take a format string + varargs, do nothing) — so the specific
  two-object-names null-pointer-dereference crash the wiki describes does not appear to fire from
  *this* call site in the retail NTSC binary this repo targets; either the crash happens via a
  different path this pass didn't find, or the report body was stripped for this release and the
  bug manifests only in a debug/other-region build. Not the same string: `base + 0x8c4` used at
  the *other* two `trickyReportError` call sites (`dll_00C4_tricky.c:1073`, `1176`, inside the
  target-object `seqId` switch in the command-target-assignment code) resolves to
  `sSidekickCommandDebugTextBlock + 0x70` = `"find command used on the wrong object\n"` — a related
  but different debug message in the same text block, not the queue-full one.
- **Weird Head Movement**: **confirmed, exact match.** `src/main/dll/maketex.c:1216`, inside
  `ObjSeq_func20` (`config/GSAE01/symbols.txt`: `ObjSeq_func20 = .text:0x80080580`):
  ```c
  fa = fa * 3.142f / 325767.0f;
  ```
  literally carries the `325767` (should be `32767`) typo, in the mode-5 "advance" branch of a
  generic turn-to-face-player step (`ObjSeqTurnState`) that samples an anim root-curve phase from
  the turn amount. The struct/function are generic sequence-turn infrastructure reused by many
  objects; the wiki's claim that the bug is "only visible in this one scene" is consistent with
  this exact code path (mode 5 with both `p6` and `p7` != `-1`) only being exercised by that
  particular Tricky-feeding-tutorial sequence's scripted data.

### Abilities / commands (Call, Find Secret, Flame, Stay, Ball)

`include/main/dll/cmenu_item_table.h` already documents `gCMenuTrickyAbilities` (the C-menu
"useTricky" section) with all five live commands and their GameBits/icons:

| bit | ability | our function(s) |
|-----|---------|------------------|
| `0x01` | Call Tricky | `src/main/dll/dll_0100_trickywarp.c` (`TrickyWarp_*`) — reachability/warp-in logic for the whistle |
| `0x02` | Find Secret | `trickyDigTunnel` (`src/main/dll/tricky_substates.c:149`) — dig up buried items |
| `0x08` | Tricky Stay! | not separately traced in this pass beyond the ability bit itself |
| `0x10` | Use Flame | `trickyFlame` (`src/main/dll/tricky_flameguard.c:139`) |
| `0x20` | Throw Ball | ball object, see Playing section above |

`Tricky_getAvailableCommands` (`dll_00C4_tricky.c:2920`) computes exactly this bitmask at runtime:
base `0x02|0x08` once `GAMEBIT_Tricky_Usable (0x4E4)` is set, `|= 0x01` if
`GAMEBIT_ITEM_TrickyCall_Got (0xDD)`, `|= 0x20` if `GAMEBIT_ITEM_TrickyBall_Bought (0x25)`, `|= 0x10`
if `GAMEBIT_ITEM_TrickyFlame_Got (0x245)` — all four GameBits already named in
`include/main/gamebits.h`. `src/main/dll/cmenu.c` reads this same mask back out of Tricky's vtable
(`+0x24`/`+0x20`) into `gTrickyHudActionMask`/`gTrickyHudItemMask`.

## Ready-to-adopt code

The five ability bits above are currently written as raw hex literals in
`Tricky_getAvailableCommands` (`dll_00C4_tricky.c`) and only exist as a comment/table in
`cmenu_item_table.h` — no enum backs them yet:

```c
/* Tricky ability bits: Tricky_getAvailableCommands()'s return value and
 * gTrickyHudActionMask/gTrickyHudItemMask (cmenu.c). Matches the "bit" column
 * of gCMenuTrickyAbilities in cmenu_item_table.h. */
enum TrickyAbilityBit
{
    TRICKY_ABILITY_CALL        = 0x01, /* Call Tricky - whistle, come to player */
    TRICKY_ABILITY_FIND_SECRET = 0x02, /* dig up buried items */
    TRICKY_ABILITY_STAY        = 0x08, /* hold position (pressure plates) */
    TRICKY_ABILITY_FLAME       = 0x10, /* fire breath */
    TRICKY_ABILITY_THROW_BALL  = 0x20, /* fetch ball bought from the shop */
};
```
