# DR_LaserCan: recovering the N64 array loops

Resolved on 2026-09-04 for EN v1.0. `drlasercannon_aimAtTarget` improved from
97.65958% to 100%, bringing all eleven functions and all 172 bytes of assigned
data to 100%. The existing GC/2.0 compiler profile is unchanged.

## Evidence from Dinosaur Planet

The sibling `../dinosaur-planet` checkout identifies object 1047 as
`DR_LaserCannon`, DLL ID `0x820C`, DLL number 733. This follows the actual
`OBJINDEX.bin` / `OBJECTS.tab` / `OBJECTS.bin` mapping, not the GameCube kiosk's
different slot numbering. The checkout has `bin/assets/dlls/733.dll` but no
decompiled C source for that DLL.

The corresponding aiming function is DLL-relative `0xAF0..0xD74`. Reproduce
the relevant evidence from the SFA checkout with:

```sh
python3 ../dinosaur-planet/tools/objlist.py --base-dir ../dinosaur-planet --id 1047
../dinosaur-planet/.venv/bin/python ../dinosaur-planet/tools/dlldump.py \
  ../dinosaur-planet/bin/assets/dlls/733.dll -d -f dll_733_func_AF0 \
  -s ../dinosaur-planet/export_symbol_addrs.txt
```

The MIPS function contains a real two-iteration loop:

- The two desired angles occupy consecutive halfwords at stack offsets
  `0x34` and `0x36`.
- At `0xCAC`, multiplication converts the degree limit to angle units;
  `0xCB4..0xCC0` writes the narrowed result back into the argument register.
- The loop at `0xCC8..0xD00` reads one signed halfword, copies it to
  destination offset `0x14`, clamps that field, advances the angle pointer
  by two bytes, and advances the destination by `0x24`.
- Its termination pointer is stack offset `0x38`, proving two input elements.
- The final absolute-value comparison is at `0xD44..0xD60`.

The destination layout agrees with DP's `HeadAnimation`: size `0x24`,
`headGoalAngle` at `0x14`. EN uses the existing `ObjJointTrackChannel` layout:
size `0x30`, `angle` at `0x14`. Two such records account for the cannon's
complete `0x130..0x190` aim region. The old `DrLaserCannonAim` type exposed
only two fields separated by padding and hid that array.

## Why the scalar reconstruction stalled

The former source used independent integer `yaw` and `pitch` locals and
manually repeated the clamp statements. Matching source uses `s16 angles[2]`
and a loop over two `ObjJointTrackChannel` records. MWCC unrolls that loop
and keeps the narrowing operations introduced while handling the array.
That produces the otherwise elusive repeated `extsh` instructions without
casts to unrelated types, a changed function prototype, or different flags.

The measured progression was:

| Source change | Aiming function |
| --- | ---: |
| Existing scalar reconstruction | 97.65958% |
| Signed-angle array and two-channel clamp loop | 99.40426% |
| Convert the limit parameter in place, as the MIPS function does | 99.53191% |
| Expand the absolute-value expression at its uses | 100% |

The final absolute value must retain its expression form, equivalent to
`ABS(self->anim.rotX - out[0].angle)`. Introducing a separate `delta` local
changes register coalescing and leaves an extra copy or loses a branch.
Earlier reports that this was an unreachable compiler residual applied to
the scalar reconstruction, not the recovered loop structure.

The direction vector also matches as a three-iteration coordinate loop.
That removes the previous redundant null check and duplicate `dp = d`
assignment while retaining exact code. This loop is supported by EN
codegen; the N64 clamp loop is the direct independent evidence that exposed
the missing array structure.

## What changed in the port

These are related implementations, not identical source snapshots. N64
aims from the object's position, requests joint index zero, computes yaw
relative to the object, and averages the two joint rotations toward their
targets. EN accepts a separate eye/muzzle position, requests joint `0xB`,
inverts pitch for object type `0x417`, and uses bounded angle interpolation.

DP's math header also documents signed-return and angle-wrapping pitfalls,
but these do not require changing EN's `getAngle` declaration. The matching
solution preserves that API and the EN behavior. The decisive carryover is
the array-and-loop source structure, expressed differently by IDO and MWCC.

## Layout and validation

The canonical header is `include/dlls/objects/609_DR_LaserCan.h`. Its state
size remains the allocation-backed `0x1AC`; the two aim records occupy
`0x60` bytes. EN object definition `0x043F`, DLL `0x0261`, has five placement
records across `dragrock.romlist.zlb` and `warlock.romlist.zlb`, all nine
words (`0x24` bytes). This establishes the setup's total size independently
of its last accessed field at `0x20`. The relevant assets were checked
against the EN ISO, and `tools/orig/romlist_params.py --search LaserCan`
reproduces the placement widths from an extracted EN files directory.

Validation with the unit marked `MatchingFor("GSAE01")`:

- All eleven functions, 4216 code bytes, and 172 assigned data bytes match.
- `tools/fnbytes.py DR_LaserCan drlasercannon_aimAtTarget` reports an exact
  940-byte / 235-instruction function.
- `python3 configure.py --matching` followed by `ninja` passes the retail
  EN DOL checksum; `ninja all_source` also exits zero.
- Canonical-header migration and formatting preserve the raw object bytes
  and symbol tables of this TU and both changed consumers.
- Formatting checks, stale-header searches, and the generated slot-609
  source-path audit pass.
