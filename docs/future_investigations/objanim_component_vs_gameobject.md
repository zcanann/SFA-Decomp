# ObjAnimComponent versus GameObject

## Question

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
