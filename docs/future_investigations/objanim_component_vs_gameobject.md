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
