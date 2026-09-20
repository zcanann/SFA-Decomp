# Asmlift experiments

[Asmlift](https://github.com/macabeus/asmlift) generates C candidates from assembly
and can rank them with objdiff. The optional SFA adapter pins npm CLI 0.8.1 and
reads retail objects already extracted by DTK. It writes only to `build/asmlift/`;
it does not replace source, claim matches, or change compiler profiles.

## Setup and use

Requires Node.js/npm, Python 3, Ninja, and this project's configured MWCC,
wibo/sjiswrap and PowerPC binutils. Tested on macOS with Node 24.15.0. The adapter
currently requires a POSIX host; native Windows command templates are not supported.

```sh
npm ci --prefix tools/asmlift --ignore-scripts
python3 configure.py --matching
ninja all_source
ninja

# Generate an integer/control-flow candidate without compiling it.
python3 tools/asmlift_sfa.py lift main/pad.c buttonGetDisabled --strict

# Compile/rank candidates with this TU's actual compiler and flags.
python3 tools/asmlift_sfa.py lift main/pad.c buttonGetDisabled --score

# A small exact smoke test.
python3 tools/asmlift_sfa.py lift main/pad.c doNothing_endOfFrame --score
```

Each invocation prints a unique workspace containing `candidate.c`,
`diagnostics.log`, `compile.json` (the compiler invocation and target),
`command.json`, and `decomp.yaml`. Keep the diagnostics: generated function bodies
may depend on synthesized declarations that are reported there. Check those
declarations and the inferred signature against the canonical headers before using
the candidate. Even an exact function score does not prove types, whole-TU data
layout, final relocation addresses, or source provenance.

With `--score`, exit 0 means asmlift reports a function match; exit 1 can mean a
nonmatch, unsupported instruction, or compilation failure. Without `--score`,
exit 0 only means lifting succeeded. Other upstream error codes are propagated;
adapter setup errors use exit 2. `--strict` refuses unsupported code rather than
leaving `ASMLIFT_ERROR` markers. Scoring implies strict mode.

Optional arguments:

- `--proto path/to/prototypes.json`: supply known signatures using upstream's
  schema, e.g. `{"setRumbleEnabled":{"params":["u8"],"returnsVoid":true}}`.
- `--elf build/GSAE01/main.elf`: supply linked symbol/type hints. This is optional
  and does not promise DWARF type recovery from MWCC debug sections.
- `--version GSAJ01`: use another configured target; first configure/build that
  version so `objdiff.json` and the extracted objects agree. DTK verifies its
  configured original DOL hash during extraction.
- `--model mwcc_233_163n` or `--model mwcc_247_107`: experiment with another
  upstream lifting model; this does **not** change the scoring compiler.

## Compiler policy

The default `mwcc_242_81` is an explicitly approximate PowerPC/MWCC lifting model.
SFA game code currently uses GC/1.3 (`mwcc_242_53` in objdiff), which upstream
does not list as a target. The adapter reads `ninja -t commands` for the owning TU,
preserves its compiler, wrappers, includes and flags, and redirects the compile
input/output to scratch files. It removes dependency-file generation and its
postprocessor. Actual flags are also passed to asmlift with `--cflags`; upstream
reports flags it cannot model, but still passes them to the compiler.

SDK/MSL/MusyX/runtime exceptions remain intact. ProDG units, including `main/zlb.c`,
are rejected. Candidate caching is disabled so scoring always recompiles. The
adapter does not inject canonical headers; asmlift synthesizes its standalone
compile prelude, which is another reason to review types and global storage.

## Observed limits in 0.8.1

Local EN tests on 2026-09-20:

| Function | Result |
| --- | --- |
| `doNothing_endOfFrame` | Exact, 0/1 differing instructions (empty callback) |
| `ColdWaterControl_getExtraSize` | Exact, 0/2 differing instructions (constant return) |
| `buttonGetDisabled` | Lifted and compiled; 3/6 differing instructions |
| `setRumbleEnabled` | Lifted and compiled; 2/3 differing instructions without prototype hints |
| `getXZDistanceSquared` | Strict lifting declined at `lfs` |
| `randomGetRange` | Strict lifting declined at `lfd` |
| MSL `strlen` | Strict lifting declined at `lbzu` |

These are smoke tests, not a representative coverage benchmark. The successful
empty callback proves the compilation/scoring connection, not broad recovery
ability. Floating-point support is a substantial missing feature for SFA; integer
loads with update and global storage/signature inference also need work.

Useful upstream extension order: recover `lbzu`/other integer update forms with
retail test cases, then model FPR loads/stores/arithmetic and ABI behavior, then
evaluate SFA's GC/1.3 behavior against the shared MWCC model. Paired-single/GQR
semantics require additional work beyond scalar floating point. Do not patch
around unsupported effects by dropping instructions.

Any adopted candidate still needs canonical types, whole-TU objdiff review,
`ninja all_source`, and the strict retail checksum gate before landing.

Adapter checks: `python3 -m unittest discover -s tools -p test_asmlift_sfa.py`.
Upstream code remains an npm dependency; no recovered retail source is vendored.
