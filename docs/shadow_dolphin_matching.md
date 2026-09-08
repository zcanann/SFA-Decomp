# Shadow renderer matching

EN v1.0, GC/1.3, 2026-09-08. All 19 functions (7,372 text bytes) and all
24,400 assigned data bytes match. `shadow_dolphin.c` is
`MatchingFor("GSAE01")` and links from C. The TU boundary, compiler version,
optimization flags, global storage layout, and expected DOL checksum are
unchanged.

## Frame setup

`shadowVolumeBeginFrame` resets the three counts, flips three selectors,
selects the volume buffer, and copies the three current buffer values to
their companion slots. The temporary selected-buffer pointer and named
zero are unnecessary. The companion slots now copy their current values
directly, preserving the retail store order.

Two explicit `const int` lvalue reads preserve the final register allocation:
`*(const int*)&lbl_803DCF20` and `*(const int*)&lbl_803DCF1C`. These access
existing `int` objects through the same type with const qualification;
they do not reinterpret bits, change signedness or width, or introduce
volatile accesses. They are a deliberate compiler workaround, not evidence
of the original source spelling. Replacing them with direct scalar reads
changes register allocation. No new arrays, data structures, dummy locals,
assembly, or pragmas are used to obtain the match.

An ordinary/instrumented GC/1.3 comparison gives identical objects. The
backend trace has 35 aligned final instructions, ten stages, no retail
differences, and 26 replayed physical color decisions. Before global
optimization the reset zero is virtual GPR 35, the selected buffer is GPR
51, and the two base-word loads are GPR 53 and GPR 54. Physical allocation
maps these to r5, r4, r3, and r0 respectively, reproducing retail.

Against the previous 18/19 object, only this function changes: eight bytes
in eight instructions, with its 140-byte size unchanged. All other function
bytes, allocated data, named symbol layouts, and resolved relocation
destinations are unchanged.

## Packed vertex streams

`ObjectShadowMesh` contains a pointer to packed signed 16-bit XYZ components
and a vertex count. Its allocation is an eight-byte header followed by
18 bytes per triangle. The definition names the pointer `coordinates` and
asserts the header size and both field offsets.

The cache conversion and cached draw track a component index advancing by
three alongside the vertex counter. Direct component accesses preserve the
retail pointer reloads, register allocation, and counter-update order.
The uncached draw reuses the stream index for `Vec3f` entries and reads
coordinates directly. Together, these lifetimes preserve the retail zero
copy as well. Separate pointer temporaries or a separate uncached index
change code generation; the index therefore keeps a neutral name.

## Validation

- Objdiff reports 19/19 functions, 7,372/7,372 text bytes, and
  24,400/24,400 data bytes matched.
- `ninja all_source` passes.
- `python3 configure.py --matching` followed by `ninja` passes the strict
  retail DOL checksum with this unit's C object selected.
- `clang-format --dry-run --Werror` passes for the source.
