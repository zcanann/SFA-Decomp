# Literal-load sequence audit

`tools/pool_value_sequence.py` compares the bytes requested by each function's
SDA21 loads in the source and retail objects. It uses the instruction's actual
load width, including both words of a double, and retains every repeated load.
Address-forming instructions, stores, out-of-range accesses, and missing objects
are unscannable rather than treated as successful comparisons.

```sh
python3 tools/pool_value_sequence.py src/main/objhits.c
python3 tools/pool_value_sequence.py src/main/objhits.c --version GSAJ01
python3 tools/pool_value_sequence.py --all .sdata2 --version GSAE01_rev1
python3 tools/pool_value_sequence.py src/dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.c --sections .sdata,.sdata2
```

The CLI verifies the selected version's configured DOL SHA-1 before inspecting
its `build/<version>/src` and `build/<version>/obj` pair. Build those objects
first; the audit does not configure or compile them. `--all` reads that version's
`report.json` and accounts for every selected row, including unscannable rows.
Its optional positional section filter remains supported.

`--sections` merges a source unit's selected pools in **instruction order**, not
section order. This can distinguish a placement mismatch from a changed constant
when the compiler emits a retail `.sdata2` value in `.sdata`. It is available for
single-source audits; it does not prove those sections have the same layout.

The former scanner silently collapsed consecutive equal loaded values. A
function loading a constant twice could therefore compare equal to one loading
it once. That behavior is now opt-in through `--collapse-repeats`, and the output
labels the weaker comparison explicitly. Historical collapsed-mode results do
not establish identical load counts.

Equal sequences establish only equal bytes and widths for the supported loads,
in address order. They do not prove equal instructions, control flow, complete
pool contents, padding, symbols, section ownership, or other relocation kinds.
Use objdiff and section/relocation audits for those separate questions.

Validation includes assembled PowerPC fixtures for repeated loads, interleaved
small-data pools, load widths, relocation addends, and truncated data. CLI tests
check version selection, rejection of a bad retail identity, explicit legacy
mode, and sweep accounting after a missing-object row. Run them with:

```sh
python3 -m unittest discover -s tools -p test_pool_value_sequence.py
```
