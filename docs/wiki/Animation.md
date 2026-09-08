# Animation

> Source: [Rena Kunisaki's SFA wiki](https://github.com/RenaKunisaki/StarFoxAdventures/wiki/Animation). Reverse-engineering notes; not independently verified here.

## Fox Animation IDs

`moveId` values observed for Fox (also usable, per the wiki, as a general "move ID" shape for
other bipeds):

* 0x0000: standing
* 0x0002: starting to run
* 0x0003: running
* 0x0016: walking
* 0x001B: idle, looking at arm
* 0x001C: idle, looking around
* 0x001E: stopping walking
* 0x002D: climb up ladder (alternates with 0x2E)
* 0x002E: climb up ladder (alternates with 0x2D)
* 0x0038: climb down ladder (alternates with 0x39)
* 0x0039: climb down ladder (alternates with 0x38)
* 0x0045: stopping running/shielding
* 0x004C: swimming slowly
* 0x004F: shielding
* 0x005B: strafing (holding L)
* 0x006E: climb down wall (alternates with 0xBE)
* 0x006F: climb up wall (alternates with 0xBF)
* 0x0070: hang on wall
* 0x0071: climb up from wall
* 0x0073: swimming
* 0x0074: swimming
* 0x00BE: climb down wall (alternates with 0x6E)
* 0x00BF: climb up wall (alternates with 0x6F)
* 0x00C0: hang on wall
* 0x00E6: stopping running
* 0x00E7: turning while running
* 0x00E8: turning
* 0x00F2: stopping running with staff
* 0x00F8: riding bike
* 0x0263: flying Arwing
* 0x0337: tied up
* 0x0348: tied up
* 0x0351: tied up
* 0x035A: get item
* 0x0404: riding SnowHorn
* 0x040D: crawling through hole
* 0x040F: standing up after crawling
* 0x0413: floating in water
* 0x041D: stopping walking with staff
* 0x0431: walking with staff
* 0x043A: running with staff
* 0x0469: attacking with staff
* 0x047B: rolling
* 0x047F: rolling with staff

## Animation Lookup

Each model also has an animation ID map in `MODANIM.BIN`. The map's offset is found by looking up
the model ID in `MODANIM.TAB`. The map's length is the next offset minus its own offset (in many
cases the length is zero).

`AMAP.TAB`/`AMAP.BIN` may be the same as `MODANIM` but for maps instead of models?

Each model has, in its model file, eight animation indices; e.g.:

| Model   | Idx0 | Idx1 | Idx2 | Idx3 | Idx4 | Idx5 | Idx6 | Idx7 |
|---------|------|------|------|------|------|------|------|------|
| Fox     | 0000 | 00FE | 0113 | 0198 | 0219 | 029C | 0000 | 0000 |
| Krystal | 0000 | 00FD | 0112 | 0197 | 0218 | 029B | 0000 | 0000 |

To look up an animation ID:

1. The high byte of the ID is an index into this table.
2. The low byte of the ID is added to the value from this table.
3. The result is looked up in the model's animation map (unclear what happens if not found). This
   value is the "real" animation ID.
4. This ID is looked up in `PREANIM.TAB`. If the upper 4 bits are 0, `ANIM.TAB`/`ANIM.BIN` are used
   instead; otherwise, the remaining bits are an offset into `PREANIM.BIN`.
5. The data from `PREANIM.BIN` or `ANIM.BIN` is the compressed animation data.

## Compression

Interpreted (per the wiki) by function `0x800074ec`.

Header:
* u32 (or 2x u16?) flags? (e.g. `0x001600EA`)
* u32 length of some sort? (e.g. `0x00002413`)
* u16 unknown (e.g. `0x4100`)

Next is the animation data, then the time data, then the "patch" data. It isn't clear from static
analysis alone where each field begins.

### Animation Data

Defines the rotation, scale, and translation of each bone. Each entry is 16 bits, masked as such:

* `0x000F`: Time Length
* `0x0010`: Scale
* `0x0020`: Translation
* `0xFFC0`: Value

* **Time Length**: if not zero, read (and consume) that many bits from the time data. The
  resulting value is a time scale; each rendered frame this is used to interpolate from one
  animation frame to the next. If Time Length is zero, this entry's value is used for the entire
  animation frame.
* **Scale/Translation**: whether these fields are present. If not, the value for the field is
  zero (values are added to the original, so scale zero means "no change").
* **Value**: the actual value for the field.

Entries are in order: X Rotation bone 0, (optional) X Scale, (optional) X Translation, Y Rotation
bone 0, (optional) Y Scale/Translation, Z Rotation bone 0, (optional) Z Scale/Translation, then X
Rotation bone 1, etc. Presumably the entry count is defined by the model's bone count.

### Time Data

A series of bit-packed values indexed from the animation data.

### Patch Data

A series of entries:
* u16 offset
* u16 unknown
* s16 value
* u16 unknown

Ends when offset = `0x1000`. Otherwise, `value` is added to the value at `offset` within the
decompressed animation data.

### Decompressed Data

The output is the raw rotation/scale/translation data for each bone for the current frame:

* s16 X/Y/Z rotation (head)
* s16 X/Y/Z rotation (tail)
* s16 X/Y/Z scale (head)
* s16 X/Y/Z scale (tail)
* s16 X/Y/Z translation (head)
* s16 X/Y/Z translation (tail)
* 28 bytes that seem unused (skipped over)

The "tail" values don't appear to affect anything. These values are absolute; the function
interpolates the input values, the time data, and the bones' normal positions.

## Vertex Animation?

Field 0xDC of the model file header points to a list of offsets to vertex adjustment data. Field
0xF9 is the number of entries in this list.

Each entry is a u16, where the top 3 bits tell whether X, Y, Z values are present. An entry with
all three bits clear marks the end of the list (in practice, always observed as `0x08AA`). The
remaining bits may be an offset or vertex number. Following the entry is between one and three
s16s for the X/Y/Z values.

The wiki author didn't know what exactly this data is used for; speculated it may relate to the
fur effect.

## In this codebase

Verified by reading the source below. This wiki page bundles two related-but-distinct systems in
this codebase: the **model-embedded skeleton animation pipeline** (most of this page) and the
**object "move" sequencing layer** (`main/objanim.c`, `include/main/objanim_internal.h`) that
picks *which* skeleton animation plays for a game object. Only the first is a close match to this
page; the "Fox Animation IDs" list is really `moveId` data consumed by the second.

### Resource files (TAB/BIN ids)

`src/main/pi_dolphin.c`'s `sResourceFileNameTable[90]` gives every named resource file a small
integer id used throughout `src/main/model.c` as the first argument to `fileLoadToBufferOffset`/
`loadAndDecompressDataFile`/`getCurrentDataFile`. Cross-referencing that table against its call
sites in `model.c` resolves every file this wiki page names:

| id (hex) | index | Resource        | Used for (verified in `model.c`) |
|----------|-------|------------------|-----------------------------------|
| 0x2c     | 44    | `MODELIND.BIN`   | `ObjModel_Load` — model id → "real" model id |
| 0x2d     | 45    | `MODANIM.TAB`    | `modelLoadAnimations` — per-model animation-map offset |
| 0x2e     | 46    | `MODANIM.BIN`    | `modelLoadAnimations` — the per-model animation-map bytes |
| 0x2f     | 47    | `ANIM.TAB`       | `gModelAnimFlagsTable = getCurrentDataFile(0x2f)` |
| 0x30     | 48    | `ANIM.BIN`       | `animLoadFromTable`/`loadAnimation` — compressed payload (non-PREANIM path) |
| 0x31     | 49    | `AMAP.TAB`       | `gModelAnimOffsetTable`, filled via `fileLoadToBufferOffset(0x31, ...)` |
| 0x32     | 50    | `AMAP.BIN`       | `modelLoadAnimations`/`animLoadFromTable` — per-frame row read straight from `AMAP.BIN` |
| 0x51     | 81    | `PREANIM.bin`    | `animLoadFromTable` — compressed payload (PREANIM path) |
| 0x52     | 82    | `PREANIM.tab`    | `animLoadFromTable` — per-`animId` u32 "flags" lookup |

This resolves the wiki's open "`AMAP.TAB`/`AMAP.BIN` may be the same as `MODANIM` but for maps?"
question with a concrete counter-example: in this codebase `AMAP.TAB`/`AMAP.BIN` are read strictly
per **model** animation id (`modelLoadAnimations`, `modelGetAmapSize`, `animLoadFromTable`), using
the exact same "next offset minus this offset" length trick the wiki describes for `MODANIM` — just
applied to `AMAP` instead, grouped in fours (`gModelAnimOffsetTable[id & 3]` /
`gModelAnimOffsetTable[(id & 3) + 1]`, refilled every 4 ids via `(id & ~3) << 2`). Nothing here
references maps; it looks like a model-animation resource, not a map one.

### Animation Lookup

- `modelLoadAnimations` (`src/main/model.c:1975`) implements this section almost line for line:
  - Reads `MODANIM.TAB` (`0x2d`) to get `tabBase`, then `MODANIM.BIN` (`0x2e`) at `tabBase` for
    `sz` bytes into `ModelFileHeader.animationHeaderBuffer` — the wiki's "map's offset found via
    MODANIM.TAB, length is model-specific" step.
  - It then scans that buffer for `-1` sentinels and, on each one, writes the next index into
    `hdr + groupSlot*2 + 0x70`. `ModelFileHeader` (`include/main/model.h`) currently spells that
    16-byte span as plain `u8 unk70[0x10]` — this **is** the wiki's per-model "Idx0..Idx7" table
    (8 × `s16`), built by splitting the model's local animation-id list on `-1` markers. See
    "Ready-to-adopt code" below.
  - `((ModelFileHeader*)hdr)->animationModelPtrs` (offset `0x64`, `STATIC_ASSERT`-adjacent to
    `animationDataSection`/`animationHeaderBuffer` at `0x68`/`0x6c`) is the per-slot pointer table
    populated by this same function — for the non-cached-moves path it's indexed as
    `animationModelPtrs[moveCacheSlot]` in `ObjModel_SampleJointTransform`
    (`src/main/model.c:3574`), returning a pointer straight at the compressed per-joint stream.
- The high-byte/low-byte "index into a table, then add" scheme in step 1-2 has a direct sibling
  in the *other* animation system: `ObjAnim_ResolveMoveIndex` (`include/main/objanim_internal.h`)
  does `animDef->moveGroupBaseIndices[moveId >> 8] + (moveId & 0xff)` — same shape, different
  table (`ObjAnimDef.moveGroupBaseIndices[0x3E]`, object-level "moves" rather than model-embedded
  animation slots). Not verified to be the *same* table as the model's `unk70[8]`; presented as an
  analogous, independently-confirmed instance of the same lookup idiom.
- Step 4/5 (`PREANIM.TAB` bit-28 test, `PREANIM.BIN`/`ANIM.BIN` fallback) is implemented **exactly**
  by `animLoadFromTable` (`src/main/model.c:2341`):
  ```c
  fileLoadToBufferOffset(0x52, &flags, id << 2, 4);      // PREANIM.TAB[id]
  if (flags & 0x10000000) {                              // upper-nibble bit set
      loadAndDecompressDataFile(0x51, ...);               // -> PREANIM.BIN
  } else {
      flags = gModelAnimFlagsTable[id];                    // ANIM.TAB[id]
      loadAndDecompressDataFile(0x30, ...);                // -> ANIM.BIN
  }
  ```
  `loadAnimation` (`src/main/model.c:2374`) is a near-identical sibling that always takes the
  `ANIM.BIN` (`0x30`) path and additionally caches the result in `gModelTexAtlasList` (see below).

### Compression

- The bit-packed decoder matching the "Animation Data"/"Time Data" description almost field for
  field is `fn_80007F78` (`src/main/render.c:340`), called from `ObjModel_SampleJointTransform`
  (`src/main/model.c:3523`). It reads two parallel 64-bit bitstream windows (`bufA`/`bufB`, refilled by the `RENDER_BITS_REFILL` macro,
  itself using the matched `render_copyPackedU64Head`/`render_copyPackedU64Tail` helpers), decodes
  a nibble "Time Length" per axis, and — when the corresponding flag bit is set — reads a second
  (scale/translation) sub-entry, interpolating between the two bitstream windows by a fractional
  phase (`frac.v`, derived from `ObjAnimState.framePhase`). This is the same shape as the wiki's
  Time-Length/Scale/Translation/Value bitfield, though this build's constant is `h & 0xFFF0` (mask
  off only the low nibble) rather than the wiki's `0xFFC0` — plausibly because this build folds the
  scale/translation flag bits into the intermediate value before a final `<< 2`/shift step, not
  because the two builds disagree on the underlying format.
  - **Address mismatch, flagged for honesty**: the wiki cites `0x800074ec` for this function; in
    this build (`GSAE01`) the matched decoder is at `0x80007F78` (`fn_80007F78` in
    `config/GSAE01/symbols.txt`). Same shape, different address — likely a different game
    revision/debug build on the wiki author's side, since `0x800074ec` itself falls inside an
    still-unmatched gap in `main/render.c` (`0x80006C6C`-`0x80007F78`) in this codebase's `.text`
    layout, immediately before `fn_80007F78`.
  - `ObjModel_SampleJointTransform` writes the current frame's bitstream cursor into
    `ObjAnimState + 0x2c` right before calling `fn_80007F78`
    (`*(u8**)((u8*)ch + 0x2c) = anim + *(s16*)(anim + 2) + bv * n;`), and `fn_80007F78` reads that
    same offset back as `posA`. `ObjAnimState` (`include/main/objanim_internal.h`) currently spells
    that span `u8 pad2c[8]` — this confirms at least the first 4 bytes of it are a real pointer
    field on the model-embedded-animation side of this shared struct, not padding. Likewise
    `ObjAnimState + 0x4c` (currently inside `pad4c[0x58-0x4c]`) is read by `fn_80007F78` as a `u16`
    ("`curB`", a byte stride to the next frame's data for interpolation) — not traced back to its
    writer in this pass.
- `ObjAnimMoveData` (`include/main/objanim_internal.h`) — `opcode`(0)/`frameControl`(1)/
  `rootCurveOffset`(4)/`frameCommands`(6) — is the actual container of the compressed stream:
  `modelAnimResetState` (`src/main/model.c:1663`) sets `channel->moveFrameData = mdl + 6` (i.e.
  `&mdl->frameCommands[0]`) and reads `frameType = mdl[1] & 0xf0` (`OBJANIM_FRAME_TYPE_MASK`,
  already `#define`d). The **same** `ObjAnimMoveData` shape backs both the model's own
  `animationModelPtrs[]` entries and the object "moves" system's `ObjAnimDef.moveData[]` /
  `&state->moveCache[slot]->moveData` (the resource starts at `0x80`) — one compressed-stream
  format, two different tables of pointers into it.

### On-disk record grammar (corpus-certified)

Certified against every animation record shipped on the rev1 disc — root `ANIM.BIN`/`PREANIM.BIN`
plus all 52 per-map `ANIM.BIN`s: 2597 ids, 2051 unique real records, every cross-container
duplicate byte-identical (10380 copies compared, 0 mismatches). This resolves the wiki's
"Compression" header guesses field by field.

**Containers.** Both `.TAB`s are 2600 `u32`s: ids 0–2596, entry 2597 = the `.BIN` size, then a
`0xFFFFFFFF` terminator and one zero pad word. An entry is a 28-bit offset (all offsets 32-byte
aligned) plus bit `0x10000000` = "this container holds the id's real record". Exactly one
container holds each real record (PREANIM: 396 ids; root ANIM: 609; the rest per-map, 546 ids are
stubs everywhere); every other container holds a uniform 32-byte null-anim stub
(`0004 0010 0000 0102` + zeros = 2 frames, 1 joint, stride 0). Two anomalies: root-`ANIM.TAB` id
2462 is flagged but stub-bodied, and PREANIM ids 1016/1017/1031/1032 are duplicated (byte-
identically) into `warlock/ANIM.BIN`.

**Record header** (the wiki's `0x001600EA 0x00002413 0x4100` example parses as):

| Offs | Type | Field (runtime reader) |
|---|---|---|
| 0x0 | u8 | always 0 in all 2051 records |
| 0x1 | u8 | `frameControl`: bits 4-7 = frame type (`0x00` = clamped, playable length `frameCount-1`; `0x10` = looping; only these two ship), bit 5 doubles as the packed-resource bit (never set on disc), bits 0-3 = `frameStep` (event-countdown divisor, `16384.0f / frameStep`) |
| 0x2 | u16 | frame-stream offset (= header + descriptor-table size) |
| 0x4 | u16 | root-motion-curve offset (0 = none; 580 records have one) |
| 0x6 | u8 | joint count |
| 0x7 | u8 | frame count |
| 0x8 | u8 | frame stride, in bytes |
| 0x9 | u8 | always 0 in all 2051 records |
| 0xA | u16[] | track descriptors, up to the frame-stream offset |

**Track descriptors** — each `u16` = `(base & 0xFFF0) | bitWidth` (bits 0-3 = per-frame delta bit
width; the same word masked `0xFFF0` is the track's base value). Grammar, per joint, three axes
each: a rotation descriptor; its bit 4 chains one more descriptor — either the axis's translation
descriptor, or (if that one's own bit 4 is set) an intermediate scale/link track whose bit 5 says
a translation descriptor still follows. Walking this grammar consumes the descriptor table exactly
and yields exactly `jointCount` groups in **all 2051 records** (chains shipped: 7910
rotation+translation, 956 rotation+link, 247 rotation+link+translation). The per-frame packet is
the concatenation of every track's delta field in descriptor order, byte-padded: Σ widths =
`stride*8 − pad`, pad 0-7, exact in all records. The decoder walks two adjacent frame packets in
parallel and lerps by sub-frame phase; rotation samples decode as `base + delta*4`, translation as
`base + delta` (`modelRenderInterpolateRootTransform`, `src/main/render.c`, reads exactly this).

**Frame stream** at the stream offset: `frameCount` packets of `stride` bytes.

**Root motion curve** at the root-curve offset: `f32 scale; s16 sampleCount;` then exactly 6 axes
of `{s16 hasSamples; if != 0, s16 samples[sampleCount]}` (`ObjAnimRootCurve`,
`include/main/objanim_internal.h`). The leading word marks presence and is not
a motion sample. The walk lands inside the record's trailing 32-byte-alignment
pad in all 580 rooted records. Encoder quirk: when `frameCount*stride` is odd the root-curve
offset is rounded *down* to even, overlapping the frame stream's final pad byte (41 records).

**PREANIM vs ANIM.** Same id space, same record format; `PREANIM.BIN` is simply the
always-resident residence class (no per-map variant exists), selected per id by `PREANIM.TAB` bit
`0x10000000` in `animLoadFromTable` — animations that must be loadable with no map pair resident.

### Vertex Animation?

This section is fully resolved in this codebase, and turns out to be the model's morph-target
(blend-shape) system, not (as far as this pass found) anything fur-specific:

- `ModelFileHeader.morphTargetPtrs` (`include/main/model.h`) sits at byte offset `0xDC` in the
  struct layout (immediately after `u8 unkD8[4]`, counting fields from the top of the struct) —
  matching the wiki's "field 0xDC points to a list of offsets" exactly. Its companion count field,
  `morphTargetCount`, has an explicit `STATIC_ASSERT(offsetof(ModelFileHeader, morphTargetCount) ==
  0xF9)` — matching the wiki's "field 0xF9 is the number of entries" exactly.
- `ObjModel_RelocateModelData` (`src/main/model.c:2586`) relocates each `morphTargetPtrs[i]` from a
  file offset to a real pointer — matching "a list of **offsets** to vertex adjustment data".
- The per-entry u16 format is implemented using a private register interface in the retail
  game (see below) in `modelReadMorphDelta`/`modelBlendMorphTargetChunk`
  (`src/main/model.c`), called from `ObjModel_ApplyBlendChannels`'s use of
  `modelBlendMorphTargets` (`include/main/model.h`) to blend up to two morph targets
  (`ObjModelBlendChannel.morphTargetA`/`morphTargetB`) into the live vertex buffer:
  ```c
  #define MODEL_MORPH_HAS_X 0x2000
  #define MODEL_MORPH_HAS_Y 0x4000
  #define MODEL_MORPH_HAS_Z 0x8000
  ```
  confirming the wiki's "top 3 bits" guess exactly (bits 13/14/15 of a u16). The retail code masks
  the remaining bits with `0x1fff` (13 bits) and uses the result directly as a **vertex index**,
  resolving the wiki's "remaining bits may be an offset or vertex number?" question in favor of
  vertex number. The terminator value the wiki observed (`0x08AA`) is consistent: its top 3 bits
  are clear (`0x08AA < 0x2000`), so it reads as "vertex 0x8AA, no deltas follow" — the loop in
  `modelBlendMorphTargetChunk` naturally stops advancing that stream once its index is beyond the
  vertex range being processed.

#### Why the morph-target pair does not byte-match

Inline assembly is banned in game code (`src/main/`, `src/track/`) with **no exceptions**. The
paired-single carve-out in `CLAUDE.md` applies only inside `src/dolphin/` SDK code. Both functions
are therefore written in plain C, and both are `NonMatching`: `modelBlendMorphTargetChunk` scores
10.784483% and `modelReadMorphDelta` 10.833333%.

The reason is a custom, non-EABI calling convention that retail uses between the two, which no C
signature can express:

- `modelReadMorphDelta` takes its stream cursor in `r20` and updates it there in place;
  it returns the three deltas in `r10`/`r12`/`r15`, uses `r21`/`r22` as scratch, has no stack
  frame, does not save `lr`, and clobbers non-volatile registers it never restores.
- `modelBlendMorphTargetChunk` is written to that convention: it stages the cursor with
  `mr r20,r24` / `bl` / `mr r24,r20` around each call and consumes `r10`/`r12`/`r15` directly,
  keeping all six deltas and both stream cursors in non-volatiles across the loop.

In C, the deltas must travel through pointer out-parameters, which forces stack homes and a
`lwz`/`stw` per component, and the callee must obey the EABI. The C version follows the decoded
stream contract. Its fixed-point wraparound is now explicitly unsigned; see [the morph-target recovery and validation](../model_morph_targets.md).

### Fox Animation IDs / move IDs

- Not present as a named enum or table in this codebase. The mechanism that *consumes* values in
  this numeric space is `Object_ObjAnimSetMove`/`ObjAnim_SetCurrentMove` (`src/main/objanim.c`),
  taking a `u32`/`int moveId`; `PlayerState.moveAnimTable` (`include/main/dll/player_state.h`,
  commented "s16 anim/move-id table base; fed to `ObjAnim_SetCurrentMove`") is Fox's own table of
  these ids, but its backing data (`lbl_80332F2C`, `lbl_80332F48`, etc. in `player.c`) is still raw,
  unnamed `lbl_` data — the individual move-id values from the wiki's list were not matched against
  specific offsets in those tables in this pass.

## Ready-to-adopt code

1. `ModelFileHeader.unk70` (`include/main/model.h`) is, per `modelLoadAnimations`, really the
   wiki's per-model 8-slot animation-group-base table:
   ```c
   /* ModelFileHeader+0x70: per-model animation-group base indices, one slot per
    * group boundary found while scanning animationHeaderBuffer for -1 markers
    * (modelLoadAnimations). This is the wiki's "Idx0..Idx7" table. */
   s16 animGroupBaseIndices[8]; /* was: u8 unk70[0x10] */
   ```
   (`animationDataFileOffset` immediately follows at `0x80`, so the slot count of 8 × `s16` = 0x10
   bytes is already implied by the existing `STATIC_ASSERT` gap between `unk70` and
   `animationDataFileOffset`.)

2. The wiki's Fox move-ID list, as `#define`s for whoever eventually names Fox's move tables (no
   existing home in this codebase — would likely live near `player_state.h` or a new
   `fox_moves.h`; values are copied as-is from the wiki, not independently re-derived here):
   ```c
   #define FOX_MOVE_STANDING              0x0000
   #define FOX_MOVE_START_RUN             0x0002
   #define FOX_MOVE_RUNNING               0x0003
   #define FOX_MOVE_WALKING               0x0016
   #define FOX_MOVE_IDLE_LOOK_ARM         0x001B
   #define FOX_MOVE_IDLE_LOOK_AROUND      0x001C
   #define FOX_MOVE_STOP_WALKING          0x001E
   #define FOX_MOVE_CLIMB_LADDER_UP_A     0x002D /* alternates with _B */
   #define FOX_MOVE_CLIMB_LADDER_UP_B     0x002E
   #define FOX_MOVE_CLIMB_LADDER_DOWN_A   0x0038 /* alternates with _B */
   #define FOX_MOVE_CLIMB_LADDER_DOWN_B   0x0039
   #define FOX_MOVE_STOP_RUN_SHIELD       0x0045
   #define FOX_MOVE_SWIM_SLOW             0x004C
   #define FOX_MOVE_SHIELDING             0x004F
   #define FOX_MOVE_STRAFE                0x005B
   #define FOX_MOVE_CLIMB_WALL_DOWN_A     0x006E /* alternates with 0xBE */
   #define FOX_MOVE_CLIMB_WALL_UP_A       0x006F /* alternates with 0xBF */
   #define FOX_MOVE_HANG_ON_WALL_A        0x0070
   #define FOX_MOVE_CLIMB_UP_FROM_WALL    0x0071
   #define FOX_MOVE_SWIMMING_A            0x0073
   #define FOX_MOVE_SWIMMING_B            0x0074
   #define FOX_MOVE_CLIMB_WALL_DOWN_B     0x00BE
   #define FOX_MOVE_CLIMB_WALL_UP_B       0x00BF
   #define FOX_MOVE_HANG_ON_WALL_B        0x00C0
   #define FOX_MOVE_STOP_RUN              0x00E6
   #define FOX_MOVE_TURN_WHILE_RUNNING    0x00E7
   #define FOX_MOVE_TURNING               0x00E8
   #define FOX_MOVE_STOP_RUN_STAFF        0x00F2
   #define FOX_MOVE_RIDE_BIKE             0x00F8
   #define FOX_MOVE_FLY_ARWING            0x0263
   #define FOX_MOVE_TIED_UP_A             0x0337
   #define FOX_MOVE_TIED_UP_B             0x0348
   #define FOX_MOVE_TIED_UP_C             0x0351
   #define FOX_MOVE_GET_ITEM              0x035A
   #define FOX_MOVE_RIDE_SNOWHORN         0x0404
   #define FOX_MOVE_CRAWL_THROUGH_HOLE    0x040D
   #define FOX_MOVE_STAND_UP_FROM_CRAWL   0x040F
   #define FOX_MOVE_FLOAT_IN_WATER        0x0413
   #define FOX_MOVE_STOP_WALK_STAFF       0x041D
   #define FOX_MOVE_WALK_STAFF            0x0431
   #define FOX_MOVE_RUN_STAFF             0x043A
   #define FOX_MOVE_ATTACK_STAFF          0x0469
   #define FOX_MOVE_ROLLING               0x047B
   #define FOX_MOVE_ROLLING_STAFF         0x047F
   ```

3. Not a header change, but worth flagging for a maintainer: `gModelTexAtlasList`
   (`src/main/model.c`, extern-declared locally, no header home) is keyed exclusively by `animId`
   at every call site in this file (`modelLoadAnimations`, `animLoadFromTable`'s macro sibling
   around line 1647, `loadAnimation`) — never by a texture id. The "Tex" in its name looks like a
   holdover from a generic shared-cache helper (`ModelList_getHeader`/`modelInitModelList`/
   `model_findIdxInModelList`/`model_adjustModelList`, all reused across several such lists in this
   file) rather than a description of what this particular list holds. A rename to something like
   `gModelAnimCacheList` would match its actual, verified usage.
