# Load-bearing puns — do-not-fix registry

A **raw pun** is a byte-offset dereference (`*(T*)(base + K)`, `(T*)(base + K)`,
an `int` walked with byte arithmetic) where a named struct field exists and the
obvious member spelling would be more readable.

Most of them are free: rewriting the offset as the field is byte-identical, and
those are not listed here — they get rewritten. This file records the ones that
are **not** free. A pun is **load-bearing** when the member spelling gives the
front end something extra to fold or common-subexpression, and retail's code
proves it did not fold. Rewriting one costs bytes, so it must not be "cleaned".

## How to read an entry

Every row carries the measurement that made the verdict, taken with the unit
rebuilt against a pristine control at the same parent and compared with
`tools/obj_equal.py` — never with the score alone.

**A score gate cannot see this class.** `454_DIMCannon`'s `modelRotation[1]`
below loses 8 bytes at an *identical* fuzzy percentage. Fuzzy is a summary, not
a comparator: gate on `obj_equal`.

**Scope is the function, not the file, and not even the spelling.** In
`tricky.c` the same `state + 0x7XX` base is load-bearing for the child-object
pointer slots and free for the float and bitfield slots *in the same function*.
Measure the site, not the pattern.

## The law that triages the rest

**FIXED vs INDEXED.** A fixed-offset re-spelling is usually free; one whose
result is then subscripted by a **variable** usually is not — the front end
folds `b + K` into the scaled index of `((S*)b)->arr[i]` while retail keeps the
two-step. A **constant** subscript is not a hazard: `((GameObject*)cursor)->childObjs[0]`
on a walking `cursor` is byte-identical (`lightmap.c`, measured).

Re-measured directly: `pi_dolphin.c` `mapCheckCurBlocksImpl` spelled
`((s16*)((char*)gObjMapBlockInfo + 0x4a))[0]` — a literal subscript on a fixed
offset. As `gObjMapBlockInfo[0x25]` / `[0x47]` the object is **byte-identical**
(md5 unchanged, 2 sites). A constant subscript costs nothing.

### Two units traps in any offset census

1. **The literal is only a byte offset when a byte-typed pointer governs it.**
   `*(s32*)(out_vec + 4)` on an `f32* out_vec` is byte **16**;
   `(Vec*)&sEnvMapBumpIndMtx + 8` is byte **96**. Eleven rows tree-wide are
   scaled this way, and reading them as bytes flips the verdict on three of
   them. Take the scale from the governing cast, and report *unknown* rather
   than assuming bytes when the pointee size is not known.
2. **Macro bodies are not sites.** 51 of the 1273 fixed-offset rows in the tree
   are inside `#define` continuations (32 in `tricky.c` alone, from
   `TRICKY_RETARGET`). They have no enclosing function and their `st` has no
   type; counting them inflates the census by 4%.

---

## Registry

### modgfx `packet.commandCount` — ten units

`(u8*)`-cast pointer difference divided by the command stride. The cast is
precisely what stops MWCC folding the pointer difference; retail **emits the
divide-by-24**. `20`, `&commands[20] - commands` and `(commands + 20) - commands`
all fold and cost **32 bytes** each.

Units: modgfx 124, 125, 126, 127, 129, 130, 131, 132, 133, 134.

### `196_Tricky/tricky.c` — `trickySelectQueuedCommandTarget`

The scan walks the queued-command records as an `int` incremented by 8 with
fixed byte offsets `+0x748` / `+0x74c` / `+0x74d`.

| spelling | fuzzy | size |
| --- | --- | --- |
| retail: `int ref = (int)state; ref += 8` | **100.0** | 316 |
| `TrickyCommand* cmd; cmd++` | 99.177216 | 316 |
| `state->commands[i]` | 97.974686 | 316 |

Both alternatives are the same length as retail, so the residual is pure
colouring — the walking `int` is what pins it.

### `196_Tricky/tricky.c` — `Tricky_updateSideCommandPrompts`, child pointers only

`*(u32*)(state + 0x7a8)` / `*(state + 0x7b0)` (write) and
`(GameObject**)(state + 0x7a8)` / `(+ 0x7b0)` (address-of), 4 sites:
100.0 → **99.0**.

The same function's `*(float*)(state + 0x7ac)` / `(+ 0x7b4)`, its
`((TrickyPackedSlots*)(state + 0x7bc))->` accesses and its
`*(u8*)(state + 0x7bc) >> n & 3` bitfield reads are **free** and have been
rewritten. Only the child-object pointer slots are load-bearing.

Two sites of the *same spelling* in `Tricky_free` (`(GameObject**)(state + 0x7a8)`
and `(+ 0x7b0)`) are **free** — they were rewritten. The source previously
carried a blanket `/* raw: arrow form shifts bytes */` comment on all six; that
comment over-claimed, and the measurement above is what replaced it.

### `main/objprint_dolphin.c` — `objFuzzRenderCb`

`*(void**)(rop + 0x38) != NULL` — a pointer-width null test on
`Shader.indTextureId` (an `s32`), 2 sites. Spelling it
`((Shader*)rop)->indTextureId != 0`: 99.82734 → **99.65468** (size 2780
unchanged).

### `523_FireFly/FireFly.c` — `firefly_activeTick`

`(f32*)(player + 0x18)` off an `int player`, 2 sites. As
`&((GameObject*)player)->anim.worldPosX`: 100.0 → **98.63603** (size 1088).

### `529/529.c` — `wmwallcrawler_update`

`(f32*)(ob + 0x24)` off a `u32 ob`. As `&((GameObject*)ob)->anim.velocityX`:
100.0 → **99.31814** (size 3860).

### `625/625.c` — `drakorhoverpad_updateMain`

`p + 4` is `DrakorHoverpadState.curve`, and the *same statement* already spells
the sibling argument `&((DrakorHoverpadState*)p)->curve` — so the pun is
deliberate, not an oversight.

| spelling | fuzzy |
| --- | --- |
| retail | **99.843346** |
| `(Curve*)&(...)->curve` (2 sites) | 99.386420 |
| both casts rewritten (4 sites) | 99.073105 |

### `dlls/engine/2/2.c` — `ObjSeq_start`, the cross-symbol reach

`base + 0x2bd4 / 0x2bd8 / 0x2bdc` where `base = gObjSeqRuntimeBuffer` lands
inside a **different `.bss` object**: `objSeqOverridePos[3]`, which
`ObjSeq_setOverridePos` writes through its own symbol. Reading it back by that
same symbol — the spelling the writer uses — is **not** free: 99.311295 →
**99.011020** (size 2904 unchanged, `matched_code` unchanged, 4 extra
instructions). Retail reaches the neighbour through the first object's symbol,
so the relocation target *name* is load-bearing here even though the address is
the same.

The whole `base + 0x3XXX` cluster in this unit is the same thing: `SeqRunTables`
and `ObjSeqRunBgState` are two composite overlays over a **run of adjacent .bss
arrays**, not one struct. That makes it the `.bss`-order lane's question (A74),
not a field-naming one.

### `454_DIMCannon/DIMCannon.c` — `modelRotation[1]`, 5 sites

**Loses 8 bytes at an identical score (99.967674 both ways.)** The only entry
here that no score gate can see. This is why `obj_equal` is the gate.

### Carried forward, measured by earlier lanes

| site | effect |
| --- | --- |
| `600_DR_CloudRun` `&base->speedMax[idx >> 1]` | −4 bytes |
| `201_Baddie` `&obj->anim.velocityX` (3 spellings) | +12 bytes |
| `598_DIMSnowHorn` `data + 0x980` (3 spellings) | +4 bytes |
| `601_SB_Cloudrun` `rotZ` / `rotY` | −4 bytes each |
| `main/objhits.c` `u32 ob = (u32)objB;` in `ObjHits_CheckSkeletonPair` | 99.734184 → 99.68724 (a B30/B31 demote device) |
| `226/226.c` `staff_setupSwipe` param re-type | 99.91625 → 99.74876 |
| `376_DFSH_Shrine` `dfshShrine_updateHoverMotion` param re-type | 100.0 → 99.7479 |

## Declined because retail's own relocations settle it — 76 rows

A raw offset that reaches **past the end of its base object** is not a field at
all. Whether the original source named the neighbour is not a matter of
judgement: the object file records it.

**The test.** Had the source written the neighbour's name, the object would
carry a relocation against that name. So compare, per unit, the number of
relocations naming the neighbour in the **retail** object against the number in
**ours**:

| retail vs ours | meaning |
| --- | --- |
| equal | retail reached those bytes by offset from the same base we use — **our spelling is already faithful; decline** |
| retail > ours | retail named the neighbour somewhere we do not — a real candidate |
| ours > retail | we named something retail reached by offset — a defect |

Run over every fixed-offset row whose byte offset exceeds its base symbol's
recorded size (76 rows, 21 base symbols, tree-wide): **76 equal, 0 candidates,
0 over-namings.** Every one is faithful as written.

This is **score-invisible** (a relocation name at an equal address scores equal,
class #70), so no other instrument in the tree screens for it.

Worked examples, all now proven rather than argued:

- `main/lightmap.c` `sceneDraw`, `q = (char*)gLightmapDrawQueue` with
  `q + 0x3f48 … + 0x3f74`. `gLightmapDrawQueue` is `0x3F48` bytes, so those 12
  float stores land in `gCloudLayerTexMatrix` (size `0x30`, exactly 12 floats),
  which `tex_dolphin.c` passes by name. Retail's `lightmap.o` nevertheless
  carries **one** `gLightmapDrawQueue` address pair and **zero** for any
  neighbour. The offsets are what retail wrote. Same for `+ 0x4108` /
  `+ 0x4164`, and for `shader.c`'s `+ 0x8588` (`gCameraPosByTransformSpace`)
  and `+ 0x417c` (`gShaderMapRomBuffers`).
- `dlls/engine/2/2.c` `ObjSeq_start` `base + 0x2bd4/8/c` → `objSeqOverridePos`.
  Retail's `2.o` references `objSeqOverridePos` **twice**, and so does ours —
  both from its own writer, neither from `ObjSeq_start`. This confirms by
  relocation what the measurement below already priced at 99.311295 → 99.011020.
- `main/textrender_gettext.c` `gGameTextLastEntry + 8` → `gGameTextBufferIndex`
  (6 sites), `main/pad.c` `gPadButtonsPrevious + 0x10` → `gPadButtonsHeld`
  (3 sites), `dlls/engine/10_expgfx` `gObjFxCrystalSparkleTbl + 0x48…0x104` →
  `gObjFxHitPulseTbl` (12 sites), `589_BossDrakor` `gBossDrakorMoveStateTable +
  0x84…0x98` → `gBossDrakorTurnMoveStates` (6 sites). Every count matches.

The `pad.c` case above was resolved on 2026-09-07. Native array definitions
available during deferred emission let MWCC generate the shared BSS base;
indexed initialization and update loops now match without cross-global
pointer offsets. See [controller input matching](pad_matching.md). The old
relocation count described the earlier reconstruction, not a required source
representation.

`.sbss` cases are the sharpest: SDA21 is one relocation per access, so the
counts are site-exact.

## Declined for want of evidence, not for bytes

These were never measured because there is nothing to name them from. They are
not load-bearing; they are simply unnamed.

- `dlls/engine/2/maketex.c` `gSaveCardImageBuffer + 0x20 / 0x2a40`,
  `gSaveCardIoBuffer + 0xa40` — byte offsets into a serialized memory-card
  image. The offsets *are* the file format; no struct exists to name them with.
- `dlls/engine/11/11.c` the `dstv` vertex record — 3 position `s16` at
  `0/2/4`, `s16` U and V at `8/0xa` derived from the texture's width and
  height, four `0xff` colour bytes at `0xc…0xf`, stride `0x10`. The one named
  vertex type in the tree, `ModgfxEffectVertex`, is a **different format**
  (`0x0A` bytes, texcoords at `6/8`), so this would be a new invented struct,
  not a recovery.
- `main/lightmap.c` `q + 0x3f48` / `+ 0x4108` / `+ 0x4164` — superseded: these
  are now **proven** faithful by the relocation test above, not merely declined
  for want of a name.

### What the tree's own offset pins cannot decide

Matching a group's offset set against all 1332 `STATIC_ASSERT`-pinned struct
types (8423 field pins) over the 140 unresolved-base groups yields **7 unique
matches and no usable lead**: 109 groups match three or more types, and every
unique match is a coincidence — `239/239.c`'s `pushable_push` "matches"
`EdibleMushroomState` and `CameraModeViewfinderState`; `666_ARWArwing` "matches"
`CameraModeStaffAnimState`. Offset-set matching alone is coincidence-dominated
and is **not** evidence. Only a group whose offsets are many *and* whose
candidate type is semantically related is informative, and outside the cases
already recorded above there are none.
