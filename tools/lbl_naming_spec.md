# lbl_ naming spec (quality-first)

You are naming auto-generated `lbl_XXXXXXXX` data globals in a Star Fox Adventures
decompilation. A rename is only worth doing when the new name is **genuinely more
meaningful** than `lbl_` and **accurate**. A vague/guessed name is WORSE than leaving
`lbl_` (which is a useful greppable worklist marker). When in doubt, SKIP the symbol.

## Process
1. Run `python3 tools/lbl_unit_context.py <unit.c>` to see each label's section, value,
   and the source lines that reference it.
2. Read the actual functions in the unit around each use to understand the role.
3. Propose a name ONLY for labels in the provided allow-list, and ONLY when you can
   justify it from evidence. Skip the rest.

## Naming convention (match existing project style)
- Read-only constants (`.sdata2`/`.sdata`/`.rodata`): prefix `g`, PascalCase, with a
  short **unit prefix** derived from the unit/function names (e.g. Door, IceBaddie, KTrex).
  Examples already in tree: `gObjAnimProgressZero` (0.0f), `gObjHitsScalarOne` (1.0f),
  `gObjAnimU32ToDoubleBias` (the int->double 0x43300000 bias).
- `.bss`/`.sbss` (uninitialized = mutable program state/buffers): prefix `g`, name from
  how the code USES it (e.g. `gIceBaddieActiveCount`, `gKTrexSpawnTimer`). These are the
  highest-value names.
- File-static strings: prefix `s` (e.g. `sIceBaddieDebugFmt`) only if the content is
  meaningful; trivial format strings like `"%d"` → SKIP.

### Float/double constants
- **Role-based** when the use reveals a clear role: e.g. a 0.017453f used as
  `angle * lbl` → `gXxxDegToRad`; a 1/64 used to scale a field → `gXxxFooScale`.
- **Value-based with unit prefix** when the value is generic and the role is unclear
  (this is explicitly allowed): `gXxxZero` (0.0), `gXxxOne` (1.0), `gXxxHalf` (0.5),
  `gXxxTwo` (2.0), `gXxxQuarter` (0.25). For odd values use a readable numeric form,
  e.g. 1.375 → `gXxxF1_375`, -0.1 → `gXxxFNeg0_1`, 100.0 → `gXxxF100`.
- Never invent a role you cannot see in the code. Generic → value-based, not a made-up role.

## Hard rules
- Names must be valid C identifiers, unique within your mapping, PascalCase after the prefix.
- Do NOT name any label outside the allow-list (those are shared across files / handled
  separately).
- Skip a label if: you can't tell what it is, it's a trivial format string, or any name you'd
  give is just `lbl_` with extra words. Skipping is correct and expected.
- Prefer accuracy over coverage. A unit where you confidently name 60% and skip 40% is a
  success.

## Output
Return ONLY a JSON object mapping old->new for the labels you chose to name, plus a short
`_notes` key per skipped label is NOT needed — just omit skipped ones. Example:
{"lbl_803E3784": "gDoorRootMotionScaleFactor", "lbl_803E3788": "gDoorZero"}
