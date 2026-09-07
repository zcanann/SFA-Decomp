# Hcurves ROM-curve matching

`dlls/engine/20_Hcurves/Hcurves_romcurve.c` is fully matching and source-linked
for EN GSAE01, using the common GC/1.3 compiler and its existing optimization
profile. All 47 functions, 32,236 code bytes, and 5,532 data bytes match.

The last mismatch was six instructions in `RomCurve_findShortestPathLink`:
the queue-distance base and final candidate-distance cursor occupied r23/r24
in the opposite order. The 1,572-byte function already had the retail control
flow and arithmetic.

The corresponding Dinosaur Planet function, `curves_func_3930` in
`src/dlls/engine/26_curves/curves.c` at reference commit
`c4340802dc9f62e1181d00cc34c3175fca6ca4be`, provided the useful source-shape lead: initialize the queue count
before storing the first distance, and index both queue arrays with that count.
The reference is evidence for the algorithm, not GameCube compiler provenance.

Replacing `queueDistances[0]` with `queueDistances[queueCount]` after initializing
`queueCount` to zero lets the cached `queueDistanceBase` local be removed.
Removing that pointer alone loses the outer queue-base initialization and
regresses allocation. Together, these changes let the frontend generate and
share the queue-array base in the needed order.

macOS LLDB captures through Wibo reproduce the ordinary compiler objects
exactly. Both captures validate 393 emitted instructions across 22 backend
stages and replay register coloring. In the baseline, the explicit queue base
is virtual GPR 46 and the generated candidate cursor is GPR 50. In the matching
source, those roles are GPR 55 and GPR 49, colored to r24 and r23 respectively.
These IDs describe the captured reconstruction, not retail source variables.

Only 13 instruction bytes change, all in the six remaining instructions.
Every other function, named-symbol layout, relocation destination, and data
section stays unchanged; anonymous literal names are renumbered at their
preserved addresses. The matching raw object SHA256 is
`2b7199be755a1ff2a4db0773c012c39d4e111e6f5a0a6c54935920a393af9123`.

The backend validator now recognizes `stbx` and `stfsx` and checks complete
indexed-store encodings for those instructions and `stwx`, including operand
register classes. Tests cover corrupted instruction bits and malformed operands.

```sh
python3 tools/unitfuzzy.py Hcurves_romcurve
python3 tools/tricky_backend_trace.py \
  --unit main/dlls/engine/20_Hcurves/Hcurves_romcurve \
  --function RomCurve_findShortestPathLink --graph \
  --output build/flag_probe/hcurves_matching_backend
```

`ninja all_source` and strict `ninja` pass after `python3 configure.py --matching`,
with a 30-second timeout on each Ninja invocation. The source-linked DOL is
byte-identical to `orig/GSAE01/sys/main.dol`.
