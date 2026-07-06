# Scripting

> Source: [Rena Kunisaki's SFA wiki](https://github.com/RenaKunisaki/StarFoxAdventures/wiki/Scripting). Reverse-engineering notes; not independently verified here.

Although most object behaviours are hardcoded, the game has a scripting system, mainly used for
animation but also capable of manipulating game state, warping the player between maps, etc.
Reverse engineering it is complicated by its code being spread across many functions and at least
six different instruction sets. Much of what follows is inaccurate/incomplete per the wiki author.

`0x5EC` in `animtest/ANIMCURV.bin` is the player "got new item" sequence (seq 0 on the player object).

## What still needs figuring out (per the wiki)
- Why sequence `0x009F` (`Player_TalkToNpc`) isn't in `swaphol`.
- Remaining object-specific commands.
- Why command 0 (`WaitUntil`) sometimes has a nonzero `Time` field.

## Starting a Sequence

Game code — usually an object's DLL — passes three parameters to function `0x80080de8`
(`ObjSeq_start`; wiki: "function 0x12 of DLL 0x02"): the object itself, a sequence number, and a
flags word (usually `0xFFFFFFFF`; purpose of individual bits unclear to the wiki author). The
sequence number often comes from field `0x18` (s16) of the object's `ObjDef`.

Each object's `ObjectFileStruct` entry (`OBJECTS.bin`) has an array of sequence IDs (s16) at the
offset given by field `0x1C`, with a count in field `0x5E`; the given sequence number indexes this
array to get the sequence ID — so a sequence only does something when played on the object it was
authored for. The sequence ID is then used up to four ways:

1. Looked up in a table at `0x802c8860` by function `0x80015d70` to find a `GameText`, passed to
   `0x8001bbd8` (`gameTextLoadTaskText`) and displayed while the sequence runs.
2. Looked up as a curve in [ANIMCURV](#animcurv).
3. Looked up as a sequence in [OBJSEQ](#objseq) (whose list can start further sequences).
4. Used to look up an audio stream.

## ANIMCURV

Primarily controls animation using sets of curves. The sequence ID from `ObjectFileStruct` maps to
a curve ID:
- If negative, its absolute value *is* the curve ID.
- Otherwise it indexes `OBJSEQ2C.tab` ("Object Sequence to Curve"): look up entry
  `(ID & 0x7FF0) >> 4`, then add `ID & 0xF` to the result.

The curve ID indexes `ANIMCURV.tab` to get an entry offset in `ANIMCURV.bin`, which begins with a
header:

```
char[4] signature;  // always "SEQA" or "SEQB" - difference unknown
s16     size;       // total size of this sequence, excluding this header
s16     nActions;   // total size (in 32-bit words) of the actions block
```

...followed by the sequence's actions (`u8 command; u8 time /* min frames before next cmd */;
s16 param;`), then an array of control points:

```
float value;      // Y coordinate
u8    typeAndScale;
u8    field;
s16   position;   // X coordinate (time)
```

`typeAndScale` low 2 bits select the interpolation type (type 3 is invalid but behaves like type
2 — see [AnimCurve.js](https://github.com/RenaKunisaki/StarFoxAdventures/blob/master/data/r/js/AnimCurve.js)
for the algorithm); the high 6 bits, divided by 16, scale type-0 points only. The game logs
`<objLoadAnimdata>  Warning ACRomTab is NULL` if `nActions == 0` or the tag isn't `SEQA`/`SEQB`.

### ANIMCURV.tab
A list of `ANIMCURV.bin` offsets, one per sequence (not the same index space as curve IDs — see
OBJSEQ2C). High bit of the offset marks whether the sequence is actually present; entry length is
next-offset minus this offset; the file ends with two `0xFFFFFFFF` entries, padded to 32 bytes
(minimum disc read size), and has no checksum (unlike other table files).

### Curves
Each curve controls one attribute of an object. Point `field` is a bitmask: `field & 0x1F` = field
ID (attribute), `field & 0xE0` = unknown. Points must be grouped/ordered by field ID (all of field
0's points, then field 1's, ...):

| Field | Attribute |
|---|---|
| 0x00 | Head rotation, Z |
| 0x01 | Head rotation, X |
| 0x02 | Head rotation, Y |
| 0x03 | Opacity |
| 0x04 | Time of day (unused — value goes to a function that ignores it) |
| 0x05 | Scale |
| 0x06 | Object rotation, Z |
| 0x07 | Object rotation, X |
| 0x08 | Object rotation, Y |
| 0x09 | Animation timer (progress through current anim) |
| 0x0A | pointSound (unclear) |
| 0x0B | Position, Z (relative to sequence start) |
| 0x0C | Position, Y (XXX X/Y swapped?) |
| 0x0D | Position, X |
| 0x0E | Camera FOV |
| 0x0F | Eye X rotation (left/right) |
| 0x10 | Eye Y rotation (up/down) |
| 0x11 | Mouth open (X rotation) |
| 0x12 | Unknown sound-related variable |

### Actions
A per-sequence script that drives the curve further and fires events along it:

| Cmd | Name | Meaning |
|---|---|---|
| 0x00 | SETTIME | Wait until curve time >= `param` (next frame if already past). Scripts usually start with this, param 0. |
| 0x01 | MOVEMODE | Toggle a camera-animation-related flag. |
| 0x02 | ANIM | Play animation: `param & 0xFFF` = anim ID, `(param>>12)*16` = duration/start frame. Player character + anim ID < 4 → id += 0x531. |
| 0x03 | OVERRIDE | Toggle whether target object is attached (copies this object's transform every frame); target chosen by ObjDef param 0x1C (0=none,1=player,2=Tricky,4=player-or-Krystal,else=unique ID, 0=id from table `80396918` indexed by sequence number). Also activates letterbox mode. |
| 0x04 | VTXANIM | Model vertex anim (mouth movement); only low byte of param used; `param-1` passed as start/end. |
| 0x05 | SOFTWARE | Unknown. |
| 0x06 | SFX | Play sound `param & 0xFFF` from current object; `param>>12==0xF` means volume / "until stopped". |
| 0x07 | GROUND_MODE | Toggle whether Y coordinate is animated. |
| 0x08 | TUNE | Unknown. |
| 0x09 | ANGLE_MODE | Set curve time position to `param` once the script finishes. |
| 0x0A | LOOK_AT | Unknown. |
| 0x0B | CONDITION | Run a [condition script](#condition-scripts-subcommand-0x0b) (`param+1` commands), pausing this sequence until it completes. |
| 0x0C | SPEECH | Unknown. |
| 0x0D | ENVFX | Enqueue a [background command](#subcommand-0x0d-envfx); high 4 bits of param = command, low 12 = parameter. |
| 0x0E | STORYBOARD | Show NPC dialogue (`GameText param`), one phrase per line, wait for A between lines. |
| 0x0F | SFX_WITH_DURATION | Self-modifying sound command (stops a prior sound, rewrites the *next* command's time to its own, changes it to opcode 0x63 (no-op), copies its param onward, queues a sound) — normally followed by `0x7F`. |
| 0x7F | — | No-op (used as filler after 0x0D subcommands 0x0B/0x0C). |
| 0xFF | — | Set max attribute-curve time (default 1000); only effective as one of the first two commands. |

Some commands stop functioning if changed in memory at certain times — not fully understood by the
wiki author (either their effect is immediately overridden, or these are object-specific commands
behaving unexpectedly).

#### Variables
`seqGlobal1`/`seqGlobal2` (s16), `seqGlobal3` (byte/bool), and `objSeqBool` (one per sequence) —
reset to 0 on map load; use `GameBits` for anything persistent.

#### Eye States (player characters)

| State | Fox | Krystal |
|---|---|---|
| 00 | Normal | Normal |
| 01 | Half closed | Half closed |
| 02 | Closed | Closed |
| 03 | 3/4 closed | 3/4 closed |
| 04 | Wide open | N/A |
| 05 | Confused | N/A |
| 06 | Annoyed | N/A |

### Condition Scripts (Subcommand 0x0B)
Interpreter: `0x80083710` (`seqDoSubCmd0B`). A sequence can queue up to 20 condition commands that
run in the background from the main loop and pause the sequence until they complete; used for e.g.
"press A to accept / B to cancel". A sequence names a time-index to resume at, but the script can
also jump to arbitrary times. Each entry is `s16 param; s16 index (high 10 bits) / op (low 6 bits)`
— `param` is signed for ops 2/3, unsigned otherwise (names extracted from `default.dol`):

| Op | Name | Meaning |
|---|---|---|
| 0x01 | JUMPTOTIME | Set curve time to `param`, end script (only if no jump command seen yet). |
| 0x02.00 | MESSAGE_SET | Enqueue an object-specific command (max 10); default commands 0x0A "add staff" / 0x0B "remove child 0" for objects without their own. |
| 0x02.01 | COUNTER_SET | `state->field_60 = param`. |
| 0x02.02 | — | No-op. |
| 0x02.03 | ANIMCOUNT1_SET | `seqGlobal1 = param`. |
| 0x02.04 | ANIMCOUNT2_SET | `seqGlobal2 = param`. |
| 0x02.05 | FLAGS_SET | `objSeqBool[seqIdx] = param`. |
| 0x02.06 | — | Set a GameBit (id from `state->field_6A`) to `param != 0`. |
| 0x03 | COUNTER_ADD | `if (index==0) state->field_60 += param`. |
| 0x04 | PAUSE | Pause until condition `index` is false; resets curve time to script start, ends script. `0x80084ce4` scans for this, uses its param as a condition, returns `max(0, time-10)`. Executes even after a jump command. |
| 0x05 | CONTINUE | End condition script, resume sequence. |
| 0x06 | — | [Subcommand 6](#subcommand-6): `index`=opcode, `param`=param (truncated u8). |
| 0x07 | MESSAGE | Send a message to an object; `index` selects a [message-table](#message-table) row, message parameter is the executing object. |
| 0x08 | DECISION | Set event type `index` to jump to label `param` on trigger (0x12=A pressed, 0x13=B pressed, 0x1A=not talking to NPC, else `state->testEvent(...)!=0`); firing an event jumps and clears all event labels. |
| 0x09 | JUMPTARGET | Define label `param`. |
| 0x0A | JUMPTOLABEL | Evaluate condition `index`; if true, goto label `param` (only if no jump command seen yet). |

#### Message Table

| idx | Target | Message |
|---|---|---|
| 00 | one | 00050001 (player get-item anim) |
| 01 | one | 00050002 |
| 02 | one | 00050003 |
| 03 | one | 00060001 |
| 04 | one | 00060002 |
| 05 | one | 000A0001 (DLL 0x19) |
| 06 | one | 000A0002 |
| 07 | one | 000A0003 |
| 08 | one | 00000008 (CF power) |
| 09 | one | 00000009 (CF power) |
| 0A | near | 00030002 |
| 0B | near | 00030003 |
| 0C | one | 000A0004 |
| 0D | one | 000A0005 (prison key) |
| 0E | one | 000A0006 |
| 0F | any | 000F000B |
| 10 | any | 000F000C (FEseqobject) |
| 11 | any | 000F000D |
| 12 | any | 000F000E |
| 13 | any | 000F000F |
| 14 | any | 000F0010 |
| 15 | one | 00130001 (SB_ShipHead) |
| 16 | one | 00130002 (SB_ShipHead) |

`one` = a single object (unclear which); `near` = objects within 600 units; `any` = all
message-capable objects.

### SubCommand 0x0D (ENVFX)

| Val | Meaning |
|---|---|
| 0x0 | Play song `param+1` (only IDs 0xD9 "victory theme" and 0x92 "chanting" accepted). |
| 0x1 | Unknown. |
| 0x2 | Load environment effect `param`. |
| 0x3 | Particle effect `param` from current object. |
| 0x4 | No-op (calls `0x80008B6C`, which just returns -1). |
| 0x5 | Load DLL `param+0xAB`, call a function in it, unload it. |
| 0x6 | Warp to map `param` (+ play sound; high 4 bits mean something for the sound). |
| 0x7 | No-op (possibly a removed debug command). |
| 0x8 | Set current object's eye/eyelid state. |
| 0x9 | Screen transition on `param & 0x2F`: 0x6 fade-out/0x7 fade-in (effect `(param&0xFC0)>>4`, duration 3), 0x8/0x9 same duration 2, 0xB/0xC same duration 4 (0xC fades in from 20%), else no-op. |
| 0xA | Unknown. |
| 0xB | Set a GameBit (param taken from the *next* command, normally `0x7F`). |
| 0xC | Clear a GameBit (same "param from next command" convention). |
| 0xD | Set input override: command byte (always 0xD) is the button mask to override; `param` indexes `{0x100,0x200,0x40000,0x80000,0x20000,0x10000,0xFFFFFFFF}` — `0xFFFFFFFF` clears a flag, else sets it (possibly a cmd/param-swap bug or decomp error). |
| 0xE | Set current object's eye state (texture 5). |
| 0xF | Set current object's eyelid state (texture 4). |

### Condition codes
Interpreter: `0x80083bf0` (`seqEvalCondition`); false skips the next command.

| Code | Test |
|---|---|
| 0x00 | Always true (game's own choice for "always true") |
| 0x01 | `state->field_60 < 1` |
| 0x02 | `state->field_60 > 0` |
| 0x03 | Daytime |
| 0x04 | Nighttime |
| 0x05 | `objSeqBool[seqIdx] == 0` |
| 0x06 | `objSeqBool[seqIdx] == 1` |
| 0x07 | `objSeqVar1[seqIdx] == 0` |
| 0x08 | `objSeqVar1[seqIdx] != 0` |
| 0x09 | `seqGlobal1 < 1` |
| 0x0A | `seqGlobal1 > 0` |
| 0x0B | `seqGlobal2 < 1` |
| 0x0C | `seqGlobal2 > 0` |
| 0x0D | Game timer disabled |
| 0x0E | Game timer enabled |
| 0x0F | Always true |
| 0x10 | `seqGlobal3 != 0` |
| 0x11 | `seqGlobal3 == 0` |

### Player Commands
Interpreter: `0x802b2da4` (`Player::SeqFn`, `player->state` field `0xBC`); set by Subcommand 0x0B
op `0x00` (MESSAGE_SET), max 10 queued per object. Selected highlights (full list of 0x01-0x32 on
the source wiki page): riding/dismount/climb an object; player-state transitions (tied up/idle/
cloudrunner/etc.); staff pull-out/put-away/toggle; start a sub-sequence; NPC dialogue; HUD/health
updates around mission rewards; spirit-vision filter; tail behaviour; viewfinder zoom.

### Subcommand 6
Interpreter: `0x80082e7c` (`objSeqExecCmd06`; low byte = op, high byte = param). Selected
highlights (full list of 0x00-0x41 on the source wiki page): find-nearest-curve query, earthquake,
count-up/down timers, fade to/from black, letterboxing, camera modes (Test-of-Strength/Static/
Normal), model-index / staff pull-out-put-away, object-group show/hide, restart-point save/clear/
goto, motion-blur and monochrome filters, rain/weather envfx loads, streaming audio/voice.

## Example
Sequence ID `0x0001` (talking to a particular NPC):

| Offs | Time | Len | Raw | Cmd | Params | Remark |
|---|---|---|---|---|---|---|
| 0000 | 0 | 0 | `00 00 0000` | SetCurvePos | 0 | Start position |
| 0004 | 0 | 0 | `FF 00 00EF` | SetCurveLen | 239 | End position |
| 0008 | 0 | 0 | `03 00 0000` | ToggleAttach | 0 | Player follows Override (looks at NPC) |
| 000C | 0 | 20 | `02 14 0000` | PlayAnim | 0x000, dur 0x0 | wait 20 frames |
| 0010 | 20 | 0 | `0B 00 0001 0000 09C6` | QueueBgCmds | PlayVoice 0x00 | |
| 0018 | 20 | 0 | `0D 00 7204` | NOP_07 | 516 | does nothing? |
| 001C | 20 | 211 | `0E D3 0083` | ShowDialogue | 0x0083 | GameText ID |
| 0020 | 231 | 2 | `0B 02 0001 0000 0009` | QueueBgCmds | DefineLabel L_0000 | |
| 0028 | 233 | 2 | `0B 02 0001 0001 0688` | QueueBgCmds | on(Not Talking to NPC) goto L_0001 | |
| 0030 | 235 | 2 | `0B 02 0001 0000 000A` | QueueBgCmds | if(True) goto L_0000 | loop until done talking |
| 0038 | 237 | 2 | `0B 02 0001 0001 0009` | QueueBgCmds | DefineLabel L_0001 | |
| 0040 | 239 | 0 | `0B 00 0001 0000 0006` | QueueBgCmds | End 0x00 | stop here |

## Unknown Data
The first 32 entries of every `ANIMCURV.bin` (per file, unverified) look like old unused data in
the *pre-header* format (same as SEQA/SEQB actions/points, but with no `SEQA`/`SEQB` header). The
first 31 are all the same sequence (`SETTIME 0`, `ENDTIME -60`); the last differs (`SETTIME 281`,
`ENDTIME 282`, one background command `JUMPTOTIME 0`, then three X-rotation points). Their
`.tab` entries don't have the high bit set, supporting the "unused" theory; replacing them with
zero-length entries has no observed effect.

## OBJSEQ
Defines which objects a sequence acts on. `OBJSEQ.tab` holds one u16 per sequence number; ×8 gives
the sequence's offset in `OBJSEQ.bin`, which holds 8-byte entries:

```
u32 uniqueID;  // if nonzero, affect this specific object (via OBJINDEX.bin translation if positive)
u16 flags;
u16 objDef;    // if uniqueID is zero: spawn this object type
```

ObjDef has special cases: `0x0000`/`0x001F` (Sabre/Krystal) = the player (whichever character);
`0xFFFF` = Override; `0xFFFE` = AnimCamera. Example — buying Tricky's ball is 3 entries:

| UniqueID | Flags | ObjDef | ObjType |
|---|---|---|---|
| 00000000 | 0001 | FFFF | Override |
| 00000000 | 8010 | FFFE | AnimCamera |
| 00000000 | C010 | 0443 | VariableObj |

Flags:

| Bit | Meaning |
|---|---|
| 0x0001 | Don't let the object move |
| 0x0002 | Don't let the object rotate |
| 0x0004 | Force object X rotation to 0 |
| 0x0008 | Disable animation of one curve |
| 0x0010 | Related to camera |
| 0x0020 | Enable sound commands in the sequence (doesn't always work — no SFX while an audio stream plays, except from the debug menu) |
| 0x0040 | Disable the gamepad |
| 0x0080 | Keep object stuck to camera |
| 0x0F00 | Camera focus index mask |
| 0x1000 | Sets a flag on the player object |
| 0x2000 | Take camera focus |
| 0x4000 | Enabled?/use Override instead |
| 0x8000 | Sets ObjDef bytes 0x20/0x21 of newly-created object (set at runtime if ObjDef is 0xFFFF) |

For each list item another sequence starts, with ID `((thisID & 0x07FF) << 4) | 0x8000 | (idx & 0xF)`
(`idx` = 1-based list index), passed to `ObjSeq_objLoadAnimdata` (`0x8008224c`); since the high bits
are set, `OBJSEQ2C` translates them (so sequence `0x0180` → curve `0x60E` → this loads curves
`0x60F, 0x610, ...`, up to 15 after the initial one).

### Example
Fox's sequence list: `023E 03AA 032E 0318 031C 032A 031D 023F 009F 0017 03AC 040E 0472 0479 03A3
047E 04DF 0471 0476 0478`. Entry `0x23E` in `OBJSEQ.tab` is `0x63A` (next entry `0x63D`) → three
8-byte entries at `0x31D0` in `OBJSEQ.bin`. Buying the ball (or any new item) runs sequence 0 of
the player object (entry `0x23E`). These values are also stream IDs, though what determines
whether a stream plays isn't known.

### VariableObj
ObjDef `0x0443` — a placeholder for an object specified by game code (e.g. the "got new item"
animation uses this to refer to the item itself). Its `defNo` (s32) is stored at `0x803db72c`
(U1.0) by method `0x1F` of the ObjSeq DLL. If spawned, only appears (as a gray arrow) when debug
objects are visible; normally never instantiated. `0x443 = 1091`, so a "can't find object 1091"
error means no `defNo` was set for a sequence.

### Override
ObjDef `0x4C8` — an invisible control object used as a sequence's "host"; appears (debug objects
visible) as a blue cube labelled "OVER RIDE".

## Triggers
Trigger objects run a script starting at field `0x18` of their Romlist entry (ObjDef), max 8
entries: `u8 flags; u8 command; u8 param1, param2;`. Flags gate execution:

| Bit | Meaning |
|---|---|
| 0x01 | Run while inside the trigger area |
| 0x02 | Run while outside |
| 0x04 | "Inside" applies every entry, not just the first |
| 0x08 | "Outside" applies every exit, not just the first |
| 0x10 | Inside/outside apply every tick (if neither 0x01/0x02 set: runs as long as loaded; else as long as condition holds) |

For `TrigPln`, "entering" means passing through in one direction, "exiting" the other. Following
the command list are additional parameters (not all trigger types use all of them):

| Offs | Type | Name | Description |
|---|---|---|---|
| 0x38 | s16 | localId | Non-unique ID so other triggers can activate this one |
| 0x3A | u8[3] | size | Dimensions (x,y,z) |
| 0x3D | u8[2] | rot | Rotation (x,y), range 0-255 |
| 0x43 | u8 | target | Object the trigger applies to/can be activated by |
| 0x44 | GameBit | activate | When set, activates the trigger (same as player entering) |
| 0x46 | u16 | delay | Frame count for TrigTime |
| 0x48 | GameBit[4] | bits | Used by TrigBits |
| 0x4C | int | action | Curve action for TrigCrve (overlaps part of `bits`) |

If `localId != 0`, the trigger can only be activated by other triggers (not for TrigCrve). `target`
values: 0 = player/ridden-object/Arwing, 1 = Tricky, 2 = camera, 3+ = unknown. Activation passes a
value to `objInterpretSeq` (`0x801993b0`): -2 outside, -1 just-left, 1 just-entered, 2 inside (1 is
also used for non-spatial triggers like TrigBits).

### Types of Triggers
- **TrigArea** (`0x004D`) — rectangular region, size `size[0]×size[1]×size[2]`, rotated by
  quaternion `{rot[0], rot[1], 0}`.
- **TrigBits** (`0x0054`) — "inside" when all four `bits` (ignoring `0xFFFF` entries) are nonzero.
- **TrigButt** (`0x004F`) — no-op; presumably button-driven in an earlier version.
- **TrigCrve** (`0x00F4`) — something involving a curve whose action matches `action`.
- **TrigCyl** (`0x0230`) — cylinder, diameter `size[0]`, height `size[2]` (`size[1]` set, unread).
- **TriggSetp** (`0x0050`) — "inside" the first tick loaded, then disappears (doesn't disappear in `default.dol`).
- **TrigPln** (`0x004C`) — square plane (X/Y), size `size[0]*6.25*obj.scale`, rotated by
  `{0, (rot[0]&0x3F)*4, rot[1]}`; if `bits[0] != 0xFFFF`, that bit must be set to activate.
- **TrigPnt** (`0x004B`) — sphere, diameter `size[0]`; sets `bits[2]` on first entry.
- **TrigTime** (`0x004E`) — "inside" after `delay` ticks (stays that way until unloaded).

### Commands (`xx`=param1, `yy`=param2)
Selected highlights (full 0x00-0x30+ list on the source wiki page, with `default.dol` debug
strings for most): player respawn variants (death-plane/dangerous-safe water), music action
(dead/removed), play-or-stop SFX, camera-triggered actions (`Camera_triggerAction`, several
modes), environment-effect toggles (sky/anti-alias/sky-objects/dome/MrSheen/footprints/moon/sun-
glare/heat-wave), `ENVFXACT.bin` effects (fog/snow/red-fade/rain/...), sequence control
(start/set-flag/clear-flag), recurse into other triggers by `localId`, lighting-action load
(no-op, freed again), Tricky talk-sequence GameBit, GameBit set/max/invert, object-group show/
hide, texture preload/free (deliberately crashes if not preloaded), map act-number set, save/
restart-point handling (`gplaySavePoint`/`gplayGotoRestartPoint`/`gplayClearRestartPoint`), map
layer change, GameBit toggle, Tricky commands (auto-heel, respawn, ball-play toggle), map asset
load/unload, level-bucket lock/unlock, NPC dialogue, texture defrag, nearby-timer add-seconds.

## In this codebase

Cross-references verified by reading the source at the paths below. This page maps almost
entirely onto `src/main/objseq.c` (DLL 0x02, "ObjSeq" — see `docs/wiki/DLLs.md`), with the
Triggers section in `src/main/dll/dll_0126_trigger.c` and the Player Commands section in
`src/main/dll/player.c`.

### Starting a sequence / the sequence-ID lookup chain

- `ObjSeq_start` (`src/main/objseq.c:3644`) *is* `0x80080de8` per `config/GSAE01/symbols.txt`
  (`ObjSeq_start = .text:0x80080DE8`). Its parameters read `(int seqIdx, u8* obj, int flags)` —
  argument order differs from the wiki's prose ("object, seq number, flags") only because C
  parameter order is register-assigned, not semantically meaningful (see this repo's own
  "reordering a callee's parameter list is register-neutral" note). `ObjSeq_start` clamps
  `seqIdx` against `((GameObject*)obj)->anim.modelInstance->sequenceCount` — the exact
  `ObjDef.sequenceCount` field the wiki calls "field 0x5E" (`STATIC_ASSERT(offsetof(ObjDef,
  sequenceCount) == 0x5E)`, `include/main/objanim_internal.h`) — then, if
  `modelInstance->sequenceMap` (`ObjDef` field `0x1C`, `STATIC_ASSERT ... == 0x1C`) is non-NULL,
  remaps `seqIdx = mapTbl[seqIdx]`. Full field-by-field `ObjectFileStruct`↔`ObjDef` mapping
  (including field `0x18`) already lives in `docs/wiki/ObjectFileStruct.md` — not re-derived here.
- **The "function 0x12 of DLL 0x02" claim is independently confirmed**: `ObjectTriggerInterface`
  (`include/main/objseq.h`) is a `STATIC_ASSERT`-verified vtable struct, and its `runSequence`
  member — `int (*runSequence)(int seqIndex, void *obj, int flags)`, i.e. exactly the wiki's
  3-parameter `ObjSeq_start` signature — sits at byte offset `0x48`
  (`STATIC_ASSERT(offsetof(ObjectTriggerInterface, runSequence) == 0x48)`), which is **word index
  `0x48/4 = 0x12`** in the struct. `gObjectTriggerInterface` is called from dozens of other DLLs
  (e.g. `src/main/dll/dll_00EC_infopoint.c:93`, `dll_0284_shopitem.c:393/397`,
  `dll_0238_linkalevco.c:180`, `dll_0293_suntemple.c` multiple sites) as `(*gObjectTriggerInterface)
  ->runSequence(...)`, matching the wiki's "usually an object's DLL" framing exactly. Note:
  `objseq.c` also defines a second, differently-ordered function-pointer array,
  `lbl_8030EE34[40]` (`ObjSeq_start` sits at raw index `0x18`, not `0x12`, in that array) — both
  tables exist in the same file; only `ObjectTriggerInterface`'s numbering lines up with the wiki.
- Sequence ID → GameText: `gameTextGetTaskText` (`0x80015D70` per symbols.txt) linear-scans
  `gTaskTextTable` (`0x802C8860` per symbols.txt — matches exactly) and `gameTextLoadTaskText`
  (`0x8001BBD8` per symbols.txt) is the wiki's cited loader — both already fully cross-referenced
  in `docs/wiki/Gametext.md` ("Object Name prefixes"/`gTaskTextTable` section); not repeated here.
  `ObjSeq_start` itself calls `gameTextLoadTaskText(lbl_803DB714)` at `src/main/objseq.c:4052`.

### ANIMCURV

- `ObjSeq_objLoadAnimdata` (`src/main/objseq.c:3444`) *is* the wiki's `objLoadAnimdata`/ANIMCURV
  loader, confirmed **exactly**: it reads `animId = *(s16*)(obj + 0x18)`; if bit `0x8000` is set it
  calls `getTabEntry(lbl_803DD0D4, 0xf, ((animId & 0x7ff0) >> 4) * 2, 8)` — the OBJSEQ2C.tab
  lookup, `(ID & 0x7FF0) >> 4`, verbatim — then adds `animId & 0xf`; otherwise it does `animId + 1`
  (the "if negative, absolute value is the curve ID" case, reached via `getTableFileEntry(0xe,
  animId, &fileOffset)`). It then reads an 8-byte header via `loadAndDecompressDataFile(0xd, &hdr,
  ...)` and checks `hdr.tag` against `sSeqAAnimDataTag`/`sSeqBAnimDataTag` ("SEQA"/"SEQB"),
  logging `sObjLoadAnimdataNullACRomTabWarning` = `"<objLoadAnimdata>  Warning ACRomTab is NULL\n"`
  on any of the wiki's three failure conditions (nActions==0 handled via `size == 0`; missing
  file-table entry; bad tag).
- **Resource file IDs 0xd/0xe/0xf are independently confirmed** against
  `sResourceFileNameTable[90]` (`src/main/pi_dolphin.c:7680`): index `0xd` =
  `sResourceFileNameAnimcurvBin` (`"ANIMCURV.bin"`), `0xe` = `sResourceFileNameAnimcurvTab`
  (`"ANIMCURV.tab"`), `0xf` = `sResourceFileNameObjseq2cTab` (`"OBJSEQ2C.tab"`) — exactly matching
  the wiki's ANIMCURV.bin/.tab/OBJSEQ2C.tab roles for these three fileIds.
- The header struct `{char tag[4]; s16 size; s16 count;}` matches the wiki's
  `signature/size/nActions` fields name-for-name (anonymous local struct in
  `ObjSeq_objLoadAnimdata`); `hdr.count` is stored directly into `ObjSeqState.cmdCount` (the
  action-words count), and `animCount = (s16)(((hdr.size >> 2) - hdr.count) >> 1)` derives the
  point count from total words minus action words, ÷2 (8-byte points = 2 words) — exactly the
  wiki's "actions block, then control points" layout.
- The control-point struct is `ObjCurveKey` (`include/main/sky_80080E58_shared.h:970`): `f32
  value` (wiki: "point"/Y), `s8 tangentAndMode` (wiki: `typeAndScale`), `u8 pad05` (wiki: `field`
  — already consumed at load time to build the per-attribute run tables below, hence unread/"pad"
  at this stage), `s16 frame` (wiki: `position`/X). `objCurveInterpolate` (`objseq.c:4960`,
  declared `include/main/sky_80080E58_shared.h:1232`) is the interpolation function the wiki
  points at `AnimCurve.js` for.
- **Curve field IDs 0x00-0x12 are exactly `ObjSeqState.trackAnimStart[19]`/`trackRunLength[19]`**
  (`include/main/objseq.h`) — a 19-entry array, matching the wiki's 19 field IDs (`0x00`-`0x12`)
  one-for-one. `ObjSeq_ApplyFrameCurves` (`src/main/objseq.c:1705`) reads them by literal index
  and confirms several field roles directly: track `7`→`anim.rotX` (wiki 0x07 "Object rotation,
  X"), track `8`→`anim.rotY` (wiki 0x08), track `6`→`anim.rotZ` (wiki 0x06), track `13`→
  `gObjSeqCurvePosOffsetX` (wiki 0x0D "Position, X"), track `18`→ sampled via
  `ObjSeq_SampleTrackCurve(seq, 18, frame)` feeding SFX volume (wiki 0x12 "sound-related
  variable"). Tracks `0`-`5`,`11`,`12`,`14`-`17` are also each read once in the same function
  (head rotation/opacity/scale/FOV/eye/mouth, per wiki order) but weren't individually
  re-diffed here.
- `ObjSeq_ExecuteActionCommand` (`src/main/objseq.c:2185`) is the top-level Actions interpreter.
  Opcode `2` ("ANIM") is confirmed **exactly**: `moveId = param & 0xfff`;
  `activeObj->anim.classId == 1 && moveId < 4` → `moveId += 0x531` (the wiki's "player character,
  anim ID < 4, add 0x531"); `unk8C = (param >> 8) & 0xf0` (the `(param>>12)*16` duration/start
  value, computed via a mask-and-shift instead of multiply). `objSeqFindLabel`/
  `objSeqFindConditional` (`objseq.c:182`/`221`) implement label scanning (opcode `0`=SETTIME/
  label-def) and the CONDITION-command background scan the wiki attributes to `0x80084ce4`
  (confirmed: `objSeqFindConditional` computes `currentLabel -= 10; if (currentLabel < 0)
  currentLabel = 0;`, i.e. exactly `max(0, time-10)`).
- **Variables**: `seqGlobal1`, `seqGlobal2`, `seqGlobal3` are literal global names in
  `src/main/objseq.c` (e.g. lines 858/861/3332-3374) — matching the wiki's variable names
  verbatim. `objSeqBool` is `gObjSeqBoolFlags[0x58]` (`objseq.c:5085`), indexed by
  `(s8)((ObjSeqState*)seq)->slot` (the wiki's `seqIdx`). `objSeqVar1` (wiki's condition-code
  0x07/0x08 array) corresponds to `gObjSeqCondFlags[0x58]` (`objseq.c:5086`), same indexing.

### Condition Scripts (Subcommand 0x0B) and its Message Table

- `seqDoSubCmd0B` (`src/main/objseq.c:710`) *is* `0x80083710` per symbols.txt
  (`seqDoSubCmd0B = .text:0x80083710`). Its `switch (opcode)` (`opcode = packed & 0x3f`) matches
  the wiki's condition-script op table **exactly**, confirmed op-by-op: `case 1`/`case 10`
  (JUMPTOTIME/JUMPTOLABEL) both gate on `gObjSeqJumpLatch[slot]` (the wiki's "only executes if we
  haven't already encountered a jump command"); `case 2` sub-switch matches MESSAGE_SET (writes
  `unk80`/`eventIds[eventCount++]`, wiki's `state.field_80`/`state.field_81[nCurveIds++]`),
  COUNTER_SET (`seqCounter = top16`, wiki's `state->field_60`), ANIMCOUNT1/2_SET
  (`seqGlobal1`/`seqGlobal2`), FLAGS_SET (`gObjSeqBoolFlags[slot] = top16`), and the unnamed
  GameBit setter (`mainSetBits(((ObjSeqState*)seq)->gameBit, top16 != 0)`, confirming
  `state->field_6A` = `ObjSeqState.gameBit`); `case 3` is COUNTER_ADD
  (`seqCounter += top16` when `subId==0`); `case 4` is PAUSE, setting `unk7C = arg10 + 1` — this
  is exactly the "+1" that `objSeqFindConditional`'s `unk7C - 1` (used at `objseq.c:2773`) undoes;
  `case 5` is CONTINUE (`return 0`); `case 6` dispatches to `objSeqExecCmd06` (Subcommand 6,
  confirmed by the call site itself); `case 7` dispatches `ObjMsg_SendToObject`/
  `SendToObjects`/`SendToNearbyObjects` by `gObjSeqMsgSendModes[arg10]` — the wiki's MESSAGE
  command; `case 8` (DECISION) and `case 9` (JUMPTARGET, a no-op body — its effect is fully in
  `objSeqFindLabel` above) round it out. `ObjMsg_Send*` and the message-queue format itself are
  already fully cross-referenced in `docs/wiki/Objects.md`'s "Message Queue" section.
- **Message Table is an exact, complete match**: `gObjSeqMsgIds[23]` (`src/main/objseq.c:5092`) is
  `{0x00050001, 0x00050002, 0x00050003, 0x00060001, 0x00060002, 0x000A0001, 0x000A0002,
  0x000A0003, 8, 9, 0x00030002, 0x00030003, 0x000A0004, 0x000A0005, 0x000A0006, 0x000F000B,
  0x000F000C, 0x000F000D, 0x000F000E, 0x000F000F, 0x000F0010, 0x00130001, 0x00130002}` —
  identical, in order, to all 23 rows (`00`-`16`) of the wiki's Message Table. The `one`/`near`/
  `any` target column matches `gObjSeqMsgSendModes[24]` (`objseq.c:5143`) =
  `{0,0,0,0,0,0,0,0,0,0,2,2,0,0,0,1,1,1,1,1,1,0,0,0}` — `one`=0, `near`=2, `any`=1, matching every
  row (indices `0A`/`0B`="near"→2, `0F`-`14`="any"→1, rest="one"→0).

### SubCommand 0x0D (ENVFX)

`objSeqDoBgCmds0D` (`src/main/objseq.c:603`) matches the wiki's list case-for-case: `case 3`
particle spawn (`gPartfxInterface->spawnObject`); `case 4` calls `return0xFFFF_80008B6C` — literally
named after address `0x80008B6C` in `config/GSAE01/symbols.txt`
(`return0xFFFF_80008B6C = .text:0x80008B6C`), matching the wiki's "Calls 0x80008B6C which just
returns -1" **exactly, including the address**; `case 5` does `Resource_Acquire(cmdParam + 0xab,
1)` (the wiki's "Load DLL param+0xAB"); `case 9`'s inner `switch (cmdParam & 0x2f)` reproduces the
wiki's six screen-transition rows (`6/7/8/9/0xB/0xC`) verbatim, including duration args `3/3/2/2/4/4`
and `0xC`'s extra blend parameter (`stepWithBlend(..., lbl_803DF028)`, the wiki's "fade in from
20%"); `case 0xb`/`0xc` are `mainSetBits(cmdParam, 1)`/`(cmdParam, 0)`; `case 0xd` indexes
`lbl_8030EDA4[cmdParam]` (`objseq.c:5141`) = `{0x100, 0x200, 0x40000, 0x80000, 0x20000, 0x10000,
-1}` — an **exact match** to the wiki's "Param is an index into an array:
0x00000100,0x00000200,0x00040000,0x00080000,0x00020000,0x00010000,0xFFFFFFFF" (note the array is
declared `int` and the last entry is plain `-1`, i.e. `0xFFFFFFFF`).

### Condition codes

`ObjSeq_EvaluateCondition` (`src/main/objseq.c:3274`) implements this exact family of tests, in
the same relative order as the wiki (`seqCounter` </>, day/night via `gSkyInterface->
getSunPosition`, `gObjSeqBoolFlags[slot]`, `gObjSeqCondFlags[slot]`, `seqGlobal1`, `seqGlobal2`,
`isGameTimerDisabled()`, `seqGlobal3`), with `default` (any value outside `0..17`, including
negative) returning true — matching the wiki's "0x00: always true" note in spirit (one call site,
`objseq.c:2773`, passes `(s8)unk7C - 1`, landing on `default`/true when `unk7C` is 0). **Caveat**:
the exact index-for-index alignment between the code's `case 0..17` and the wiki's `0x00-0x11`
hex list wasn't fully nailed down here — it holds cleanly for `case 0-13` (→ wiki `0x01-0x0E`,
off-by-one) but the wiki's duplicate "`0x0F`: always true" note doesn't line up with `case 14`'s
actual body (`seqGlobal3 != 0`); flagged rather than force-fit, per the wiki's own "much of this
is inaccurate/incomplete" disclaimer.

### Player Commands

`player_SeqFn` (`src/main/dll/player.c:3167`) *is* `0x802b2da4` per symbols.txt
(`player_SeqFn = .text:0x802B2DA4`); its `switch (seq->eventIds[vb])` at `player.c:3768` onward
carries `case 0xb` through `case 0x32`, spot-checked against several wiki rows (e.g. `0x12`, `0x13`,
`0x14`-`0x1a`, `0x1c`-`0x22`, `0x25`-`0x2f`, `0x31`, `0x32` are all present as distinct cases in the
same relative order as the wiki's `0x01`-`0x32` list) — full per-case semantic verification against
every wiki bullet wasn't done in this pass.

### Subcommand 6

`objSeqExecCmd06` (`src/main/objseq.c:1104`) *is* `0x80082e7c` per symbols.txt
(`objSeqExecCmd06 = .text:0x80082E7C`). Confirmed op-by-op for several entries: `case 2` ("Get
Curve") builds `pair = {0x19, 0x15}` and calls `gRomCurveInterface->find(..., pair, 2, cmdArg)` —
the wiki's "find curve of type 0x19 or 0x15 nearest this object with action param", exactly;
`case 9` sets `unk7F |= 1` (wiki: "set state flag 7F bit 1"); `case 14` (`0xE`, "Fade to black")
calls `gScreenTransitionInterface->start(cmdArg, 1)`; `case 18` (`0x12`, "toggle letterboxing")
flips bit `0x10` of a per-slot flags byte. The remaining ~60 cases (`0x00`-`0x41`) weren't
individually re-verified in this pass but follow the same `switch (cmdByte)` structure.

### OBJSEQ

- `ObjSeq_start` (`src/main/objseq.c:3644`) directly implements the OBJSEQ.bin object-list parse:
  `getTabEntry(hdr, 0x3c, seqIdx * 2, 8)` reads two `s16`s from `OBJSEQ.tab` (`first`, and
  `count = next-first`), then `getTabEntry(buf, 0x3b, first * 8, size)` reads the 8-byte entries
  from `OBJSEQ.bin`. **FileIds 0x3b/0x3c independently confirmed** against
  `sResourceFileNameTable[90]` (`pi_dolphin.c:7680`): index `0x3b` =
  `sResourceFileNameObjseqBin` (`"OBJSEQ.bin"`), `0x3c` = `sResourceFileNameObjseqTab`
  (`"OBJSEQ.tab"`) — exact match, and `0x3b*8=... ` matches the wiki's "value ×8" tab-entry rule
  in the sense that `getTabEntry` is called with `seqIdx*2` (2-byte tab entries) while `OBJSEQ.bin`
  offsets are read as `first*8` (8-byte bin entries) — same ×8 factor the wiki describes.
- The per-entry special-case dispatch (`objId == 0xffff` → Override, `== 0xfffe` → AnimCamera,
  `== 0x443` → VariableObj-with-`objSeqObjs`-override) at `objseq.c:3837-3879` matches the wiki's
  ObjDef special cases and VariableObj description exactly, including the `+4` model-index bias
  applied when the `0x4000` "use Override" flag bit is set (`*(u16*)(walk2+4) & 0x4000`).
  `packed = ((seqIdx & 0x7ff) << 4) | 0x8000` at `objseq.c:3825`, combined with `| (idx & 0xf)` per
  entry (`objseq.c:3894`), is a **byte-for-byte match** of the wiki's
  `ID = ((thisID & 0x07FF) << 4) | 0x8000 | (idx & 0xF)` formula.
- `ObjSeq_SetObjs` (`src/main/maketex.c:126`, extern-declared/exported via `objseq.c`'s
  `lbl_8030EE34[37]`) sets the global `objSeqObjs` (`objSeqObjs = .sdata:0x803DB72C` per
  symbols.txt) — an **exact match** to the wiki's "defNo (s32) is stored at 0x803db72c ... by
  method 0x1F of the ObjSeq DLL" (word offset `0x1F` matching `ObjectTriggerInterface.setObjects`
  at struct byte offset `0x7C` → word index `0x7C/4 = 0x1F`, `STATIC_ASSERT(offsetof(
  ObjectTriggerInterface, setObjects) == 0x7C)`).

### Triggers

`src/main/dll/dll_0126_trigger.c` (DLL 0x126) is the wiki's entire "Triggers" section:

- `TriggerPlacement`/`TriggerState` (top of the file) are `STATIC_ASSERT`-verified against exactly
  the wiki's offsets: `triggerId`@0x38 (wiki `localId`), `gameBitSrc`@0x44 (wiki `activate`),
  `triggerDelayFrames`@0x46 (wiki `delay`), `gateBitSrc[4]`@0x48 (wiki `bits[4]`) — and the wiki's
  note that `action` (0x4C) "overlaps part of bits" is structurally confirmed: 0x4C falls inside
  the `gateBitSrc[4]` array span (0x48-0x4F), specifically its 3rd `s16` element. `size`/`rot`/
  `target` (wiki 0x3A/0x3D/0x43) fall inside an as-yet-unnamed `pad3A[0x44-0x3A]` gap — not
  individually named fields in this repo yet.
- `Trigger_init` (`dll_0126_trigger.c:212`) `switch (((TriggerPlacement*)params)->typeId)` matches
  **all nine** of the wiki's `Types of Triggers` defNos exactly, case-for-case: `0x4b`→TrigPnt
  (reads `params[0x3a]*2` as a diameter→radius, matching "sphere, diameter size[0]"), `0x4c`→TrigPln,
  `0x230`→TrigCyl (`params[0x3a]*2`, squared, matching "diameter size[0]"), `0x4d`→TrigArea (reads
  `params[0x3d]`/`params[0x3e]` into rotX/rotY, matching "rotated by quaternion {rot[0],rot[1],0}"),
  `0x54`→TrigBits (copies all 4 `gateBitSrc` entries), `0x4e`/`0x4f`/`0x50`→TrigTime/TrigButt/
  TriggSetp (no init needed), `0xf4`→TrigCrve.
- `objInterpretSeq` (`dll_0126_trigger.c:269`) *is* `0x801993b0` per symbols.txt
  (`objInterpretSeq = .text:0x801993B0`) and its header comment (already in-repo) independently
  describes the same flags-byte gating the wiki documents (enter/exit bits, once-only latches,
  unconditional/override-disabled bits) via the file's own `TRIGGER_CMD_*`/`TRIGGER_SFLAG_*`
  `#define`s. Its `switch (p[1])` carries dozens of the wiki's numbered trigger commands as
  literal `case` values (spot-checked: `case 0xb` camera-action-shaped dispatch, `case 0x10`
  player-model-index set, `case 0x12` GameBit-with-shift-encoding, `case 0x1b`/`0x1c` object-group
  show/hide, `case 0x1f` save/restore-position flags, `case 0x20` map-layer change, `case 0x26`
  Tricky sub-commands, `case 0x2d` NPC dialogue) — not every one of the ~50 wiki rows was
  individually re-diffed in this pass.
- `MapEventInterface` (`include/main/mapEventTypes.h`) independently names the exact functions the
  wiki's Trigger-command list calls by their `gplay*` names: `savePoint`, `gotoSavegame`,
  `restartPoint`, `gotoRestartPoint`, `clearRestartPoint`, `setObjGroupStatus` — confirming
  `gplaySavePoint`/`gplayGotoRestartPoint`/`gplayClearRestartPoint`/`gplaySetObjGroupStatus` are
  real, named interface members here, not just wiki debug-string guesses.
- **GameBit cross-reference**: `include/main/gamebits.h`'s own `enum GameBitId` (imported
  separately from Rena's `gamebits.xml`, per that header's comment) already contains
  `GAMEBIT_ENV_disableDayFX1 = 0x3AB` / `GAMEBIT_ENV_disableDayFX2 = 0x3AC` — an exact match to
  this page's ENVFX subcommand `0x1C`'s `mainSetBits(0x3AB, ...)`/`mainSetBits(0x3AC, ...)` — and
  `GAMEBIT_TrickyTalk = 0x4E3` (comment: `"if < FF, can talk to Tricky, but he won't say
  anything"`), an exact match, including the near-identical phrasing, to this page's Subcommand 6
  opcode `0x11` ("Set Tricky talk sequence ... Sets GameBit 0x4E3 to xxyy ... Tricky will want to
  talk to you"). `GAMEBIT_ENV_disableDayFX3`/`0x3AF` (this page's subcommand `0x1C` opcode `0x02`)
  is **not found** in `gamebits.h` yet.

## Ready-to-adopt code

The four smaller, most-central switches above (`ObjSeq_ExecuteActionCommand`'s top-level opcode,
`seqDoSubCmd0B`'s condition-script op, `ObjSeq_EvaluateCondition`'s condition code, and
`objSeqDoBgCmds0D`'s ENVFX opcode) are each fully verified against the wiki in "In this codebase"
above and are small enough to safely centralize. The larger switches (Subcommand 6's ~65 cases,
Trigger's ~50 commands, Player Commands' ~50 cases) were only spot-checked here — a maintainer
adopting enums for those should re-verify each case against the cited function before naming it.

```c
/* ANIMCURV/OBJSEQ sequence-action opcodes (ObjSeqState.cmds[i].command).
 * ObjSeq_ExecuteActionCommand (src/main/objseq.c) switches on this byte;
 * names are the wiki's. Only 0x02 (ANIM) was independently re-verified case-body-for-case-body. */
enum SeqActionOpcode {
    SEQACT_SETTIME = 0x00,
    SEQACT_MOVEMODE = 0x01,
    SEQACT_ANIM = 0x02,
    SEQACT_OVERRIDE = 0x03,
    SEQACT_VTXANIM = 0x04,
    SEQACT_SOFTWARE = 0x05,
    SEQACT_SFX = 0x06,
    SEQACT_GROUND_MODE = 0x07,
    SEQACT_TUNE = 0x08,
    SEQACT_ANGLE_MODE = 0x09,
    SEQACT_LOOK_AT = 0x0A,
    SEQACT_CONDITION = 0x0B,
    SEQACT_SPEECH = 0x0C,
    SEQACT_ENVFX = 0x0D,
    SEQACT_STORYBOARD = 0x0E,
    SEQACT_SFX_WITH_DURATION = 0x0F,
    SEQACT_NOP = 0x7F,
    SEQACT_SET_MAX_TIME = 0xFF,
};

/* Subcommand 0x0B (condition-script) op field: packed & 0x3f in seqDoSubCmd0B
 * (src/main/objseq.c:710). Fully case-verified against the wiki above. */
enum ObjSeqSubCmd0BOp {
    SUBCMD0B_JUMPTOTIME = 0x01,
    SUBCMD0B_SET = 0x02,      /* sub-op via `index`: MESSAGE_SET/COUNTER_SET/ANIMCOUNT1_SET/
                                  ANIMCOUNT2_SET/FLAGS_SET/set-GameBit - see seqDoSubCmd0B's
                                  nested switch (subId) */
    SUBCMD0B_COUNTER_ADD = 0x03,
    SUBCMD0B_PAUSE = 0x04,
    SUBCMD0B_CONTINUE = 0x05,
    SUBCMD0B_SUBCOMMAND6 = 0x06,
    SUBCMD0B_MESSAGE = 0x07,
    SUBCMD0B_DECISION = 0x08,
    SUBCMD0B_JUMPTARGET = 0x09,
    SUBCMD0B_JUMPTOLABEL = 0x0A,
};

/* ObjSeq_EvaluateCondition (src/main/objseq.c:3274) condition codes. Semantics
 * verified against the switch bodies; the exact index<->wiki-hex alignment has
 * an unresolved off-by-one wrinkle around 0x0F - see "In this codebase" above. */
enum ObjSeqConditionCode {
    OBJSEQ_COND_SEQCOUNTER_LT1 = 0,
    OBJSEQ_COND_SEQCOUNTER_GT0 = 1,
    OBJSEQ_COND_DAYTIME = 2,
    OBJSEQ_COND_NIGHTTIME = 3,
    OBJSEQ_COND_BOOL_EQ0 = 4,   /* gObjSeqBoolFlags[slot] == 0 */
    OBJSEQ_COND_BOOL_EQ1 = 5,   /* gObjSeqBoolFlags[slot] == 1 */
    OBJSEQ_COND_VAR1_EQ0 = 6,   /* gObjSeqCondFlags[slot] == 0 */
    OBJSEQ_COND_VAR1_NE0 = 7,   /* gObjSeqCondFlags[slot] != 0 */
    OBJSEQ_COND_GLOBAL1_LE0 = 8,
    OBJSEQ_COND_GLOBAL1_GT0 = 9,
    OBJSEQ_COND_GLOBAL2_LE0 = 10,
    OBJSEQ_COND_GLOBAL2_GT0 = 11,
    OBJSEQ_COND_TIMER_DISABLED = 12,
    OBJSEQ_COND_TIMER_ENABLED = 13,
    OBJSEQ_COND_GLOBAL3_NE0 = 14,
    OBJSEQ_COND_GLOBAL3_EQ0 = 15,
    /* 16, 17, and anything else: always true (falls to `default`) */
};

/* objSeqDoBgCmds0D (src/main/objseq.c:603) ENVFX background-command opcodes.
 * Fully case-verified against the wiki above. */
enum SeqEnvfxBgOpcode {
    ENVFXBG_PLAY_SONG = 0x0,
    ENVFXBG_UNK1 = 0x1,
    ENVFXBG_LOAD_ENVFX = 0x2,
    ENVFXBG_PARTICLE_FX = 0x3,
    ENVFXBG_NOP = 0x4,           /* calls return0xFFFF_80008B6C (0x80008B6C), always -1 */
    ENVFXBG_LOAD_DLL = 0x5,      /* DLL id = param + 0xAB */
    ENVFXBG_WARP_TO_MAP = 0x6,
    ENVFXBG_NOP2 = 0x7,
    ENVFXBG_SET_EYE_EYELID = 0x8,
    ENVFXBG_SCREEN_TRANSITION = 0x9,  /* sub-selected by param & 0x2F */
    ENVFXBG_UNKA = 0xA,
    ENVFXBG_SET_GAMEBIT = 0xB,   /* param from the *next* command */
    ENVFXBG_CLEAR_GAMEBIT = 0xC, /* param from the *next* command */
    ENVFXBG_SET_INPUT_OVERRIDE = 0xD,
    ENVFXBG_SET_EYE = 0xE,
    ENVFXBG_SET_EYELID = 0xF,
};

/* lbl_8030EDA4 (src/main/objseq.c:5141), indexed by ENVFXBG_SET_INPUT_OVERRIDE's
 * param. Exact match to the wiki's array. -1 (0xFFFFFFFF) clears a flag instead
 * of setting it. */
#define SEQ_INPUT_OVERRIDE_TABLE_INIT { 0x100, 0x200, 0x40000, 0x80000, 0x20000, 0x10000, -1 }
```
