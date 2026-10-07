# ObjAnimComponent versus GameObject

## Object animation API recovery (2026-10-06)

The public move, progress, blend, root-curve and move-table APIs now take
`GameObject*`. Their callers use complete objects from object allocation,
canonical object globals and object DLL entry points. The misleading `void*`
“ABI-facing callback” rationale has been removed: the four affected APIs are
called directly, and their implementations recover `&obj->anim` internally.
The change does not establish whether the original source had a distinct
component typedef; the existing `GameObject.anim` layout remains unchanged.

The previous `Object_ObjAnimSetPrimaryBlendMove` selects `activeState`
(layer 1), while `Object_ObjAnimSetSecondaryBlendMove` selects `currentState`
(layer 0). They are now `ObjAnim_SetLayeredBlendMove` and
`ObjAnim_SetCurrentBlendMove`; the other `Object_ObjAnim*` operations likewise
use `Layered` names. Dinosaur Planet's `include/sys/objanim.h` and
`src/objanim.c` at `c4340802dc9f62e1181d00cc34c3175fca6ca4be` provide corroborating
whole-object signatures and current/layered state selection. These are
semantic SFA names, not a claim to have recovered original SFA identifiers.

Propagating the contract exposed `short*` object parameters in
`player_advanceMove` and `enemyObjAnimUpdate`, an `int*` boss callback, and
integer object parameters in three Player handlers. Their declarations,
callback table and direct consumers now agree on `GameObject*`; affected
rotation, position, velocity and hit-reaction accesses use canonical fields.

Validation covers EN, EN rev1, JP, PAL and PAL rev1: `all_source`, strict retail
DOL equality and full objdiff inventories with completion metadata removed.
Every affected TU is exact. Across all source objects, section contents,
symbol locations and resolved relocations are unchanged after accounting for
the five intentional function renames. The existing TRK `__exception` vector
carving and MusyX `sal_volume` discarded-data report artifacts are unchanged;
all five source-linked DOLs are byte-identical to their verified originals.

## Shared movement/controller contract (2026-10-06)

The engine DLL 15 interface now takes `GameObject*` and `BaddieState*`, with
285 direct calls audited across 20 source files. Player, ground enemies,
rideable characters and bosses pass their evidenced shared controller prefix.
The descriptor embeds that same typed interface, so its function initializers
are checked against the public declarations instead of being independently
cast to generic callbacks. The registry retains its explicit descriptor cast.

`player_modelMtxFn` was not a matrix operation: its `mtx[3..5]` accesses are
the object's local position at `0x0C`, `0x10` and `0x14`. It is now
`PlayerControl_ApplyPositionNudge`; the related `player_render2` is
`PlayerControl_ApplyYawNudge`. The old forward-velocity interface names are
corrected accordingly. `dll_0F_func0B` and `dll_0F_func13` are now
`PlayerControl_UpdateTurnFromRootMotion` and
`PlayerControl_ApplyDirectionalVelocity`. The latter's floating-point
arguments precede its angle, matching the previously cast Player call.
`gPlayerMoveOverrideObject` also replaces the integer `playerOverride`.

`player_setState` now calls its exit callback with `(obj, state)`, removing a
false zero-argument cast that happened to preserve the argument registers.
Animation advancement uses the canonical `ObjAnimEventList`, including its
root-motion fields and indexed event IDs, instead of a duplicate record and
byte-offset iteration. Dinosaur Planet's `18_objfsa` at the revision above
corroborates the nudge operations, callback arguments and unused time-step
argument in target turning; SFA's own transition order remains unchanged.
These semantic names do not establish an original SFA filename.

Player's sequence callback keeps separate typed views of its full state and
controller prefix. The explicit `(BaddieState*)inner` prefix conversion
preserves MWCC's separate register identities; replacing it with
`&inner->baddie` merges them and changes allocation. The full state no longer
needs an integer handle. This is a compiler constraint on an evidenced common
prefix, not a host-port accommodation.

All five versions pass `all_source`, strict retail DOL equality and full
objdiff inventories. Every affected TU is exact, and every source object's
section contents, symbol locations and resolved relocations remain unchanged
after the five intentional renames. The two pre-existing report artifacts
described above remain unchanged.

## Shared object collision contract (2026-10-06)

Engine DLL 21 is the object/terrain collision service previously mislabeled
`PathControlInterface` and `curves_*`. Its nine exports now share a typed
`ObjCollisionInterface` embedded in the descriptor: whole `GameObject*`
objects, `ObjCollisionState*` records, float point/radius arrays and signed
terrain query bytes. All 161 interface calls across 22 source files use this
contract. The height-query slot at `0x1C` is also declared instead of being
an opaque pointer. The confirmed TU, including its save helpers, stays intact.

Callers now pass their actual `objectCollision` member instead of a flags
word or `state + 4`. Player, CloudRunner, SnowHorn and HighTop use typed state
locals and the evidenced `heightPadding`/`subtype` fields. Surface-tilt
updates no longer pass the state through an integer. The former
`curves_countRandomPoints` resolves four floor samples; its name is now
`ObjCollision_ResolveFourPointFloor`.

The contract exposed concrete false data interpretations. WallCrawler's
three-byte "collision bone" string was the leading bytes of a `10.0f`
radius; its final zero byte is now part of the float, with the next symbol's
address unchanged in all five versions. Baddie's subnormal float was a query
type byte followed by three unexplained bytes, now kept opaque. Zero point
triples, collectible radius `3.0f`, IceSmash radius `4.0f` and BombPlantSpore
radius `5.0f` have their actual types. EarthWarrior copies a four-byte query
record instead of loading an integer and passing its address as an array.

Dinosaur Planet's `include/dlls/engine/27.h` and `src/dlls/engine/27/27.c` at
the revision above corroborate the separate hit-point/terrain colliders and
the nine-slot interface. They support the recovered roles, not original SFA
identifiers or a replacement layout. Foxhollow's EarthWarrior collision-state
access is another lead consistent with the retail-backed member recovery.

All five versions pass `all_source`, strict retail DOL equality and full
objdiff inventories. Every affected TU and every active game TU is exact.
Across the complete source-object inventory, sections, named symbol offsets
and resolved relocations are unchanged apart from intentional renames and
WallCrawler's recovered final radius byte. The two existing library report
artifacts described above remain unchanged. This recovers the target game's
contract without adding native-port accommodations.

## Remaining question

Is `ObjAnimComponent` a genuine standalone component from the original source,
or is it an artificially separated reconstruction of the first `0xB0` bytes of
the original `GameObject` / `ObjInstance` record?

## Current evidence

- `GameObject.anim` is at offset zero, and `sizeof(ObjAnimComponent) == 0xB0`.
  `GameObject.objectFlags`, the first recovered tail field, is at `0xB0`.
- The two pointer values are therefore identical for an ordinary game object:
  `obj == &obj->anim` at the ABI level.
- `ObjAnimComponent` contains much more than animation state: transforms,
  velocity, object IDs, placement and model pointers, the DLL pointer,
  hit-reaction state, a target object, and hitbox state.
- `ObjHitbox_SetSphereRadius` and `ObjHitbox_SetCapsuleBounds` only read the
  common head (`rootMotionScale` at `0x08`, `hitReactState` at `0x54`, and
  `hitboxScale` at `0xA8`). They could consequently be expressed with either
  an `ObjAnimComponent*` or a `GameObject*` without changing field addresses.
- Several reconstructed specialized records embed an `ObjAnimComponent` at
  offset zero. This may demonstrate deliberate base-record reuse, but it may
  instead mean those object records have only been recovered through `0xB0`.
- In `arwingandrossstuff_update`, changing the sphere-radius call from an
  integer object handle to a pointer expression caused MWCC to swap the two
  long-lived registers (`obj` and its state pointer). An explicit
  integer-to-pointer boundary restored the function to 100%. This is evidence
  about the original caller's source type, but does not by itself prove the
  underlying record was a distinct animation component.

## Why it matters

Using `GameObject*` for object-system APIs would remove many casts and may be a
more plausible expression of the original source. Conversely, collapsing a
real reusable base component into `GameObject` would make nonstandard object
records less accurate and could disturb matching through source-level type
changes even though the ABI pointer value is unchanged.

## Suggested investigation

1. Census every struct that embeds `ObjAnimComponent` and determine whether
   code accesses fields beyond `0xB0` through the same allocation.
2. Census functions taking `ObjAnimComponent*`: separate animation-only
   routines from general object, hitbox, placement, model, and DLL routines.
3. Test `GameObject*` signatures on a small dependency cluster, including the
   sphere/capsule hitbox functions, and compare all callers with objdiff.
4. Check source strings, other-region artifacts, and reference projects for
   original names such as `ObjInstance`, inheritance patterns, or a distinct
   animation subrecord.
5. Only merge or rename the types once the allocation and caller evidence
   explains both ordinary objects and the specialized offset-zero records.
