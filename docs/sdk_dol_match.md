# SDK DOL matcher

`tools/sdk_dol_match.py` is the cross-game SDK matcher for cases where a reference project already knows its split bounds and also has the matching `orig/<version>/sys/main.dol`.

The tool is meant for SDK recovery work, especially when:

- the current SFA split assignment is suspicious
- several nearby SDK files have similar total text size
- a reference project has a likely source file but we want stronger evidence before wiring it into `splits.txt`

It complements `tools/sdk_import_probe.py` rather than replacing it.

## What it compares

For each reference split window, the matcher:

- reads the exact `.text` bytes from the reference `main.dol`
- uses the reference project's `symbols.txt` to break that window into functions
- normalizes PowerPC instructions by masking relocation-heavy fields such as branch targets and many immediates
- scores candidates by function-count shape, per-function masked similarity, whole-window masked similarity, and masked opcode n-gram overlap

This makes the pass more robust than raw byte hashing, while still being strict enough to catch exact SDK carryover.

## Default references

By default the tool scans the current high-value English rev 0 reference set:

- `animal_crossing:GAFE01`
- `pikmin2:GPVE01`
- `marioparty4:GMPE01`
- `twilight_princess:GZ2E01`

Config shorthands such as `GMPE01` and `GAFE01` auto-resolve to the rev 0 config when there is a single `_00` match.

## Main modes

Use it in one of two directions.

1. Current SFA source to reference SDK windows

This answers "what known reference source does our current split look most like?"

```bash
python tools/sdk_dol_match.py -v GSAE01 --source src/dolphin/os/__ppc_eabi_init.c --limit 8
```

You can also target a raw SFA window instead of an assigned source:

```bash
python tools/sdk_dol_match.py -v GSAE01 --range-start 0x802928F4 --range-end 0x802929A8 --limit 8
```

2. Reference source to current SFA windows

This answers "where in SFA does this known SDK source likely live?"

```bash
python tools/sdk_dol_match.py -v GSAE01 --reference pikmin2:GPVE01 --reference-source Dolphin/os/__ppc_eabi_init.cpp --target-range-start 0x80244000 --target-range-end 0x80248538 --limit 5
```

For math hunting, it is usually best to narrow the target range around the suspect cluster:

```bash
python tools/sdk_dol_match.py -v GSAE01 --reference pikmin2:GPVE01 --reference-source Dolphin/MSL_C/PPC_EABI/math_ppc.c --target-range-start 0x802928F4 --target-range-end 0x80295318 --limit 8
```

## Reading the results

Each match prints:

- total score
- per-function masked similarity
- whole-window masked similarity
- masked n-gram overlap
- size score
- exact function-size matches

The tool also emits a simple verdict:

- `source-likely`: strong candidate for retargeting or importing the reference source
- `structural`: likely same family or same neighborhood, but still needs manual verification
- `weak`: not strong enough to trust on its own

Treat `source-likely` as evidence, not proof. Confirm with `sdk_import_probe.py`, the surrounding split layout, and a normal build / objdiff pass before changing ownership.

## Suggested workflow

1. Use `sdk_import_probe.py --rank-assigned` to find suspicious current SDK assignments.
2. Use `sdk_dol_match.py` in reference-to-SFA mode to see which current EN windows line up with likely reference SDK files.
3. Use `sdk_dol_match.py` in SFA-source mode to see which reference projects agree on the same source family.
4. If the result is still strong, import or retarget the candidate source and verify with `python configure.py -v GSAE01`, `ninja`, and objdiff.

## Notes

- The matcher is currently tuned for SDK-style code, not arbitrary gameplay code.
- The default path filter is intentionally SDK-biased: MSL, Dolphin, Runtime.PPCEABI, and TRK.
- Exact matches are possible. For example, `dolphin/os/__ppc_eabi_init` hits `0x80247438-0x802474CC` in SFA as a perfect cross-game match.
