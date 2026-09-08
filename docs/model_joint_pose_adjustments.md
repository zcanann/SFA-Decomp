# Joint pose adjustments

Target: EN v1.0 (`GSAE01`), game compiler GC/1.3.

`ObjAnimComponent.jointPoseData` holds one 0x12-byte `ObjJointPose` per
`ObjDef.jointData` binding record. Both the size calculation and placement in
`loadCharacter` use `jointCount * 0x12`. The joint-binding records have a
separate variable stride, `modelCount + 1`: a joint tag followed by one model
joint index per bank. An index of 0xff excludes that binding from that bank.

The builder at `0x80028664` exposes all nine signed-halfword adjustments:

| Pose record offset | Shared field | Offset from decoded rotation base |
| --- | --- | --- |
| 0x00, 0x02, 0x04 | rotation[0..2] | 0x00, 0x02, 0x04 |
| 0x06, 0x08, 0x0a | scale[0..2] | 0x0c, 0x0e, 0x10 |
| 0x0c, 0x0e, 0x10 | translation[0..2] | 0x18, 0x1a, 0x1c |

These are additive adjustments, not interpolation weights. The decoded
64-byte `RenderJointWork` slots have two rotations at +0x1c, two scales at
+0x28, and two translations at +0x34. The adjustment consumers at `0x800075fc` and `0x80007830` add a halfword
to the selected component; the paired-frame path applies it to both poses.
The scale adjustment itself is signed even though decoded scale storage is
unsigned. Blink animation independently confirms the second rotation component
by writing opposite signed angles to the left and right eyelid joints.

For each nonzero component the builder emits four halfwords: the current
move's component offset, the previous move's component offset, and the same
adjustment twice. A pair of 0x1000 halfwords terminates the table. The move's
signed joint-map byte selects a 0x40-byte work slot; its signed load and shift
are preserved. Map rows come from the state's native move-cache slots or the
file's eight-byte-aligned per-move mapping rows, depending on the file flag.

The shared definition lives in `include/main/joint_pose.h`, replacing the
renderer-local nine-element array. Allocation and pose finders use its size;
the model builder and blink writer use its named component arrays. The raw
byte pointer in `ObjAnimComponent` remains for existing cursor-based callers.

Validation: all 1,002 source object hashes are unchanged, including the model,
object-allocation, and objprint objects. The complete objdiff report is
unchanged; the blend-table builder remains 1,264 bytes at 100%. Both the
strict retail checksum and `all_source` pass. This recovery does not alter
the separate private-ABI joint-matrix reconstruction.

## Aiming lookup reuse

`objJointTracksAimAtTarget` uses the existing `objFindJointVecByKey` inline
helper for the same packed binding scan. Both select the last matching key
whose active-bank index is not 0xff and return null when the model or binding
is absent. Replacing the duplicated scan also allows its one-element result
array to become an ordinary pointer.

Under GC/1.3 this fixes the five register differences in the lookup, improving
the 1,332-byte function from 99.81982% to 99.90991%. Its instruction sequence
and size already matched retail. Five operand differences remain in the
pitch-rate clamp; they exchange the limit and doubled-divisor registers.
The other 39 function bodies, allocated data, named symbol layouts, and
resolved relocation destinations are unchanged. One anonymous float literal
is renumbered without moving its storage or changing its six references.
Both `ninja all_source` and the strict retail checksum build pass. Formatting
already passes and leaves the compiled object unchanged.

## Typed aiming channels

The optional channel argument to `objJointTracksAimAtTarget` is now an
`ObjJointTrackPair*`. The retail path writes yaw at +0x14, pitch at +0x44,
passes the two 0x30-byte channel records to the tracking helpers, and advances
by 0x60 for the next joint. The existing pair definition expresses that layout
without repeated casts or a literal byte stride. Both moveLib callers convert
their existing backing buffers at the API boundary; null still selects the
direct pose-adjustment path.

The objprint and moveLib objects remain byte-for-byte identical. This API
recovery does not resolve the five pitch-clamp register-operand differences:
the retail positive limit uses r7 and the doubled divisor r6, whereas the
current compiler exchanges those registers. The staff segment transform also
retains its existing expression-order and register differences. No compiler
profile or matching status changes accompany this recovery.

## Exact pitch-rate clamp

The final five operand differences are resolved by keeping the pitch-rate
limit as `s16` and converting the floating-point product directly to that
type. The prior source converted through `s32` and stored the narrowed result
in an `int`. These are not interchangeable inputs to MWCC's optimizer even
though the emitted conversion and sign extension were already correct.
Changing only the local's type is byte-neutral; removing only the intermediate
cast leaves seven operand differences. The direct conversion into the native
halfword local reproduces all 333 retail instructions under the unchanged
GC/1.3 profile. The local is named `pitchRateLimit` to distinguish it from
the subsequent frame-scaled pitch adjustment.

`objJointTracksAimAtTarget` becomes 100% exact (1,332 bytes), taking the TU
to 39/40 exact functions. Only the five register-operand words change;
all other function bodies, allocated non-text sections, and named symbol
positions are unchanged. Six relocations rename one anonymous float literal
without changing their offsets, types, addends, or physical destinations.
No helper, forced storage, inline assembly, or compiler override is added.

The target comparison covers the whole compiled function, including its
conversion behavior and both clamp bounds. No new host runtime test is claimed
for out-of-range float-to-halfword conversion: host C conversion semantics are
not a substitute for the matched Gekko instructions. Both `ninja all_source`
and the strict retail checksum target pass with thirty-second limits. The TU
remains `NonMatching` because `staffUpdateSegmentTransforms` is not yet exact.
