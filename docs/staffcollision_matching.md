# Staff-collision matching

`src/dlls/modgfx/90/90.c` matches EN v1.0 (`GSAE01`) completely as of
2026-09-07: `StaffCollision_spawn` is 1,408 bytes, and all owned data matches.
The existing GC/1.3 compiler and optimization settings are unchanged.

## Recovered return contract

The function returns the last `s16` result from `ModgfxInterface.spawnEffect`.
If the requested count is nonpositive, it returns zero. The old `void` signature
discarded that behavior. In retail, the otherwise unexplained `li r3,0` at entry
supplies the empty-loop result; the last spawn call supplies `r3` when the loop
runs, and the epilogue preserves it.

The public function and `StaffCollisionSpawnFn` now both return `s16`. This
also agrees with the signed handle returned by the underlying modgfx interface
and the neighboring slot 91 spawner. Existing staff-collision callers discard
the result, which had concealed the mistaken signature.

## Matching source shape

The packed resource block is held through a single-entry local resource-pointer
table, following the neighboring spawner's source pattern. Assignment to that
addressable local lets MWCC form the resource base directly in its saved register;
the scalar pointer declaration retained an intermediate copy. This is a
codegen-backed reconstruction, not proof of the original declaration's spelling.
The resource data, vertex layouts, and descriptor remain unchanged.

The loop bound is declared after the loop index. With the returned handle and
resource table in place, this restores the retail color accumulators in
`r24/r23/r22`, loop index in `r21`, and count in `r20`. Controlled compiles show:

| Source | Objdiff | Remaining differences |
| --- | ---: | --- |
| Original void function | 99.21875% | Register assignments and an entry copy/zero difference |
| Restore the s16 result alone | 98.52273% | Register assignments and one extra resource copy |
| Result plus resource table | 99.517044% | 32 register differences |
| Move count after index too | 100% | None |

The old copy/rematerialization classification missed a real return value. A
source correction can initially lower the score while exposing the structure
needed for a complete match.

## Verification

- All 352 emitted instructions match retail; raw function bytes match too.
- All initialized section bytes, section sizes and alignments, and shared named
  symbol layouts match the extracted retail object.
- LLDB captures 20 compiler stages and replays 122 physical register choices
  with zero retail differences. Instrumented and ordinary objects are identical.
- `python3 configure.py --matching`, bounded `ninja all_source`, and bounded
  strict `ninja` pass with this unit linked from source (`main.dol: OK`).
- Recompiling the other 23 affected units against the previous callback header
  produces identical raw objects, confirming that the return-type correction
  does not change their code or data.

Reproduce the compiler capture with:

```sh
python3 tools/tricky_backend_trace.py --unit main/dlls/modgfx/90/90 \
  --function StaffCollision_spawn --graph \
  --output build/flag_probe/staffcollision_backend
```
