# Sky TU matching

Engine slot 5 (`src/dlls/engine/5/5.c`) reaches 100% for EN v1.0 on
2026-09-07: all 57 functions, 16,924 code bytes, and 776 data bytes.
Its common GC/1.3 compiler and existing `cflags_dll_noopt_noautoinline`
profile remain unchanged.

## Sun and moon rendering

The remaining function was `renderSunAndMoon`, at 98.840%. Its source emitted
488 instructions against retail's 487: 59 operand differences and one extra
zero load. The earlier register/pool classifications in the band-width worklist
did not exhaust the source-level possibilities.

Reusing one `phase` local for the sun and moon calculations resolves all the
floating-point register differences. These calculations execute sequentially;
the sun's phase is no longer needed when the moon's phase is computed. Moving
the separate moon-phase declaration alone did not help.

The final zero-load mismatch came from the expanded slot-flag getter. The TU
already exposes `skyGetSlotFlag80`, which returns the selected light's flag or
zero when sky state is absent. Sharing that implementation through the private
inline `skyReadSlotFlag80` recovers both render checks. The public getter remains
an emitted, exact 40-byte function for external consumers. Simply marking the
public function inline omitted that required body, so it is not the final
source structure.

The unchanged compiler's diagnostic trace helps explain the result. Before the
getter recovery, the visibility-zero destination was GPR virtual register 39,
outside late value numbering's eligible range of 41–179. The rotation-zero
destination was a separate eligible temporary, leaving two `li` instructions.
The final source has one zero load, with destination 156 inside the range
40–179, and reproduces retail's register assignment. This is evidence about the
reconstructed source's optimization, not proof of the original helper's name.

The position conversions now cast directly from float to `s16`, and the sun's
rotation uses the canonical `anim.rotX` field. Both cleanups preserve their
existing instructions. Local names describe the shared phase, rotation records,
direction, camera, saved far plane, and transition timer.

## Data and linkage

Only `renderSunAndMoon` changes function bytes; it shrinks from 1,952 to 1,948
bytes. All allocated non-text sections remain byte-identical to the starting
source object. Their sizes and all shared named data-symbol offsets agree with
the retail split. The following text symbols move back four bytes to their
retail offsets; compiler-generated anonymous names may change.

The first complete source link exposed an existing retention omission:
`sSkyUnusedColors`, the 60-byte `.data` table at retail address `0x8030F2E0`, was
present in the source object but discarded by the linker. Adding it to the
existing `force_active` list retains the evidenced bytes. The previously listed
unused final `.sbss` word remains retained. No declaration order, section
alignment, split boundary, or expected checksum changes are needed.

## Validation

- Whole-TU objdiff: all 57 functions and all data exact.
- `python3 configure.py --matching`, then `ninja all_source` and strict `ninja`,
  each Ninja invocation with a 30-second timeout: pass; `main.dol: OK`.
- Diagnostic backend capture: 487 aligned instructions, 13 stages, no retail
  differences; GPR simplification and all 144 color decisions replayed.
- Instrumented and ordinary compiler objects have identical SHA-256:
  `92f1ec750323cfd6964092cc4080e2f60b4fbf55318193e20794a6aa76d001e2`.

Regenerate the diagnostic capture with:

```sh
python3 tools/tricky_backend_trace.py \
  --unit main/dlls/engine/5/5 --function renderSunAndMoon --graph \
  --output build/flag_probe/sky_matching_backend
```
