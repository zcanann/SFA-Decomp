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
