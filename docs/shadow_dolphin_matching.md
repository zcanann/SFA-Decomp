# Shadow mesh matching

EN v1.0, GC/1.3, 2026-09-07. `objDrawShadowCasterMesh` now matches all
1,132 text bytes with the existing TU compiler and optimization profile.
`shadow_dolphin.c` advances from 17/19 to 18/19 exact functions and from
99.90288% to 99.978294% fuzzy match. All 24,400 assigned data bytes match.
The TU remains `NonMatching`.

## Packed vertex streams

`ObjectShadowMesh` contains a pointer to packed signed 16-bit XYZ components
and a vertex count. Its allocation is an eight-byte header followed by
18 bytes per triangle. The recovered definition names the pointer
`coordinates` and asserts the header size and both field offsets.

The cache conversion and cached draw track a component index advancing by
three alongside the vertex counter. Direct component accesses preserve the
retail pointer reloads, register allocation, and counter-update order.
The uncached draw reuses the stream index for `Vec3f` entries and reads
coordinates directly. Together, these lifetimes preserve the retail zero
copy as well. Separate pointer temporaries or a separate uncached index
change code generation; the index therefore keeps a neutral name.

## Remaining frame setup

`shadowVolumeBeginFrame` still differs at eight instructions: the zero used
for four count resets occupies r4 instead of r5, while the selected volume
buffer occupies r5 instead of r4. Both versions have 35 instructions.
A GC/1.3 backend capture reproduces the ordinary object exactly and observes
the zero in virtual GPR 38 and the selected pointer in GPR 32 before global
optimization. Physical allocation maps them to r4 and r5. Declaration,
initializer, aggregate, selector, and inline-helper variants tested in this
session do not resolve the swap. This is an unresolved source reconstruction,
not evidence that a different per-function compiler profile is justified.

## Validation

- Compared with the starting source object, only `objDrawShadowCasterMesh`
  changes: 24 instruction bytes, with its size unchanged. All other function
  bytes, allocated data, named symbol layouts, and resolved relocation
  destinations are unchanged.
- A diagnostic link substituting this C object for its retail object differs
  only at the eight frame-setup instructions, at 0x80062818, 0x8006281C,
  0x80062820, 0x80062824, 0x80062868, 0x8006286C, 0x80062870, and 0x80062884.
  All allocated section addresses and lengths, and every other byte, match.
- `ninja all_source` and the strict matching DOL checksum build pass.
