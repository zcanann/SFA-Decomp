# Model hit-sphere update

`objUpdateHitSpheres` at EN v1.0 `80027B40` combines animation hit-mask
selection with double-buffered sphere updates. Its public declaration now
identifies the model, model file, target object, and source object. Both direct
rendering callers use these canonical types. The optional matrix argument
continues to override per-sphere joint lookup when non-null.

## Hit-mask state

When the source model has animation hit-state data, the updater divides
`ObjHitReactState.activeEntryByteCount` by four, selects a word using current
move progress, and clamps indices above the last word. It does not add a
lower-bound clamp. Without animation hit-state data it copies the source's
current `ObjHitsPriorityState.objectHitMask`; without source state it uses zero.

These values are masks, not pointers to samples. `ObjHits_CheckObjectHitVolumes`
consumers in `src/main/objhits.c` shift `objectHitMask` and `skeletonHitMask`
right by four or mask off their low nibble before checking hit volumes.
The updater first copies the target's old `objectHitMask` into
`skeletonHitMask`, then writes the newly selected mask into `objectHitMask`.
The code retains the existing canonical field names.

The animation-entry buffer is still declared with its shared general type;
this consumer explicitly reads its words as `u32`. The existing two-use
temporary is retained as `maskWord`: first the buffer address, then the selected
word. A separate typed pointer and direct mask assignment eliminate the
retail `mr r6,r0`. The reset-mode decrement retains an unsigned byte store
followed by a signed-byte test and clamp to zero.

## Sphere records

The updater toggles `OBJMODEL_BUFFER_FLAG_HITSPHERE_SELECT`, selects the new
active sphere buffer, and retains the opposite buffer as the previous frame.
The removed `ObjHitBufs` overlay duplicated fields already present in `ObjModel`.

Each 24-byte `ModelHitSphereDef` supplies its signed joint index at `+0`,
radius at `+4`, and center at `+8`. Each 16-byte `ObjModelHitSphere` receives
the radius multiplied by the source object's root-motion scale and the center
transformed by the selected matrix. The previous buffer's X/Z positions are
adjusted by saved-minus-current map offsets. When source and target differ,
the first sphere also updates the target object's local and world positions
from the matrix origin. Layout assertions now cover each accessed record field.

The paired byte counters retain their proven storage shape: replacing them
with scalars changes the initial `mr` to `li`, and array indexing changes
register allocation. Their strides now use the canonical record sizes.

## Validation

The updater remains byte-exact at 704 bytes under game compiler GC/1.3.
All 85 model function bodies, allocated section bytes, and named symbol layouts
are unchanged. Anonymous literal names change, with identical normalized
relocation destinations. The rendering consumer's complete object is unchanged.
The model unit retains 74/85 exact functions and 92.268425% fuzzy match.
Separate formatting is byte-neutral. The strict retail checksum and
`all_source` builds validate linkage and the public declaration at both callers.
