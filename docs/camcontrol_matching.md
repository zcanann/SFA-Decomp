# Camera-control TU: complete EN match

`src/dlls/engine/1_camcontrol/camcontrol.c` now matches EN GSAE01 completely
and links from source. The strict retail DOL checksum passes.

| Measure | Before | Complete |
| --- | ---: | ---: |
| Unit fuzzy match | 99.98165% | 100% |
| Exact functions | 42 / 43 | 43 / 43 |
| Exact code bytes | 9,560 / 10,900 | 10,900 / 10,900 |
| Exact data bytes | 836 / 836 | 836 / 836 |
| `camcontrol_applyState` | 99.850746% | 100% |

## Blend update and clamp

The remaining nine differences were an `f2`/`f3` swap between the initial
blend-progress load and the clamp's merged zero/one/result value. The
instruction sequence and function size were already correct.

The blend update now uses ordinary compound subtraction, and the clamp reads
the camera field directly instead of copying it into `prog`:

```c
camera->blendProgress -= camera->blendStep * timeDelta;
camera->blendProgress = (camera->blendProgress < 0.0f) ? 0.0f :
                       ((camera->blendProgress > 1.0f) ? 1.0f : camera->blendProgress);
```

The local Dinosaur Planet reference's `CamControl_update_camera` in
`src/dlls/engine/2_camcontrol/camcontrol.c` uses the same compound decrement
for its blend value. Its easing calculation differs from SFA, so the clamp
and resulting code are validated against the EN retail instructions.

Both edits are necessary under the current GC/1.3 profile. Compound subtraction
alone retains all nine register differences; removing the temporary alone
also retains them. Together they match the complete TU without changing
compiler flags, function order, public interfaces, or TU boundaries.

## Compiler evidence

LLDB's baseline graph assigns the initial progress load (virtual FPR 41) to
`f3` and the merged clamp value (virtual FPR 65) to `f2`. With both source
edits, these roles are represented by virtual FPR 65 and virtual FPR 43 and
receive retail's `f2` and `f3`, respectively. Virtual IDs describe the observed
compiler records, not original source variables.

The final capture aligns all 335 instructions across 14 stages and replays
68 floating-point register-color choices with zero retail differences. The
ordinary and instrumented objects have the same SHA-256:
`c0405dee7978a8afb44055d990ba8563c079d55549d37723b72b08735970300d`.

This supersedes the old source-spelling closure for this function. The earlier
flag experiments reproduced the register swap while regressing siblings;
the paired source edit preserves all 42 already-exact functions.

## Validation

All 43 raw function bodies match retail. Named symbol layouts, relocation
records, and all non-text sections are unchanged from the baseline object.
The source's ten-byte `.sdata` payload has the same six trailing alignment
bytes supplied at link time as before; the source-linked DOL passes the
strict retail checksum.

```sh
python3 tools/unitfuzzy.py dlls/engine/1_camcontrol/camcontrol.c
python3 tools/tricky_backend_trace.py --unit main/dlls/engine/1_camcontrol/camcontrol \
  --function camcontrol_applyState --graph --register-class fpr \
  --output build/flag_probe/camcontrol_complete_backend
python3 configure.py --matching
# Each Ninja invocation must have a 30-second timeout.
ninja all_source
ninja
clang-format --dry-run --Werror src/dlls/engine/1_camcontrol/camcontrol.c \
  include/main/dll/CAM/dll_0001_camcontrol.h
```
