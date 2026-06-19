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

### Float/double constants (CONSERVATIVE — owner direction)
- **Name ONLY** floats with a clear ROLE (e.g. a 0.017453f used as `angle * lbl`
  → `gXxxDegToRad`; a 1/64 scaling a field → `gXxxFooScale`) OR a genuinely
  distinctive/meaningful value: Pi, deg2rad/rad2deg, the int→float/double
  `0x43300000` conversion biases, a named threshold/limit the code clamps to.
- **LEAVE plain generic constants as `lbl_`.** A plain 0.0 / 0.5 / 1.0 / 60.0 /
  250.0-type value with no clear role must STAY `lbl_` — do NOT value-name it
  (`gXxxF60`, `gXxxHalf`, `gXxxZero` are NOT wanted). `lbl_` is a clean worklist
  marker; a value-encoded rename is worse than leaving it.
- Never invent a role you cannot see in the code. No clear role + not distinctive
  → skip (leave `lbl_`).

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
