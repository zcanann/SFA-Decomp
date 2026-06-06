# Deref-Conversion Playbook (typed struct access, byte-identical .o)

Field-tested reference from the deref-cleanup wave: converting Ghidra-style
raw offset derefs (`*(T *)(state + 0xNN)`, `*(f32 *)((char *)p + 0xNN)`,
`piVar[0x2d0 / 4]`) to typed struct member access without changing a single
byte of comparison-relevant output. Companion to the matching recipes in
CLAUDE.md (proposed for integration there by the repo owner; this file is
the staging ground). Tooling: `tools/deref_struct_convert.py` (inventory ->
header-emit -> convert, JSON config per TU), `tools/deref_o_gate.py` (the
byte gate), `tools/deref_maps/*.json` (shared-record field maps).

## 1. The conversion methodology ladder

Work down this ladder per function; stop at the first rung that gates clean.

1. **Struct insertion is byte-neutral by construction** when the member's
   offset, width and signedness mirror the spelled deref exactly. Build the
   struct FROM the deref census (majority type per offset, overlap demotion),
   never from guesswork: an import-guessed width that disagrees with even one
   converted site flips an instruction (recipe #58 family).
2. **Strategy by base type:**
   - `int X = *(int *)(obj + 0xb8);` locals: retype the local
     (`T *X = *(T **)(obj + 0xb8);`) when every other use of X is a handled
     context; wrap surviving bare uses `(int)X` (the scarab `(int)sub`
     house pattern). Null tests must stay int-typed: `(int)X == 0`.
   - Params and bases with load-bearing raw arithmetic: keep the int
     declaration and use inline casts `((T *)state)->field` (proven byte-exact,
     #77 family). NEVER add a fresh typed-local copy to a high-pressure fn -
     the extra web is the #77(d) all-or-nothing trap.
   - `int *` word-scaled bases (`piVar[K]`, `*(f32 *)(p + 0x17)`): inline
     casts only; multiply offsets by the element size; `register` qualifiers
     on params must be stripped before type matching (a silent skip cost 65
     conversions in weaponE6 until caught).
   - GLOBAL-table hoists (`u8 *base = lbl_X;`, `(u8 *)(int)lbl_X` launders):
     DO NOT convert - the spelling is recipe-#80 load-bearing (savegame.c,
     FRONT/dll_3E). Global POINTER variables to heap records
     (`*(f32 *)((int)lbl_803DD548 + 0x11c)`) DO convert via
     `((T *)lbl)->field` - #83a value-numbers global-derived launders through.
3. **Width discipline is keyed on the SPELLED deref type, not semantics:**
   u8/s8 flips `extsb`, u16/s16 flips `lhz`/`lha`, int/u32 flips
   `cmpwi`/`cmplwi`. The converter only replaces exact-type matches
   (aliases: short=s16, s32=int, float=f32, uint=u32, ghidra
   undefined/byte/ushort to u8/u16/u32; char is NOT aliased - signedness
   ambiguous, leave char-spelled sites raw). A void* field may absorb any
   pointer-spelled deref (load is width-identical; the compile+byte gate
   rejects bad contexts). Integer-spelled derefs of pointer fields stay raw -
   that is the null-test launder (`*(int *)&obj->extra != 0`) and it is
   correct, not residue.
4. **Spelling preserves that the gate will enforce anyway - save the round
   trip:**
   - An offset used as a bare ADDRESS anywhere in a fn (call arg
     `(char *)p + 0x5d4`, stored interior pointer) excludes that offset from
     conversion FN-WIDE: converting its derefs breaks MWCC's address-CSE
     (`addi rX; lfs 0(rX)` becomes folded displacement loads - the
     fn_802A36EC class).
   - Stride walkers (`p += 3`, `base + idx*0xb0 + off`) and variable-index
     forms stay raw.
   - `(int)`-cast deref spellings on LOCAL bases may be #83a launders -
     converting them changes the expression tree; let the gate decide, expect
     reverts.
5. **All-or-nothing holdouts are EXPECTED**, usually the family's main
   update/SeqFn (andross_update: one inline cast flipped a saved-reg pair and
   cascaded 1642 instructions). Convert the rest of the file, leave the
   holdout raw, note it in the commit message. Do not grind.

## 2. The gate doctrine

THE GATE: every touched TU's .o must verify before commit. The 4-point check:

1. All sections byte-identical EXCEPT the @NNN allowances below.
2. Relocation tables byte-identical (locals resolve by index, so this holds
   even when names drift).
3. Symbol table identical after masking local `@NNN` NAMES only - addresses,
   sizes, bindings, sections unchanged.
4. main.dol md5 + report.json totals unchanged to the digit.

`tools/deref_o_gate.py baseline.o current.o --rebuild <repo-root>` performs
1-3 and owns the rebuild. Use md5 (not sha1) when quoting dol hashes - the
team convention; a hash-algorithm mix-up once produced a phantom "divergence".

**The @NNN pool-name class (score-neutral, recipe #70 extension).** MWCC
numbers anonymous pool symbols from a global counter that ticks per
fine-grained expression/type construct (a redundant `(int)` cast shifts it
+1; removing ~1000 cast-deref spellings drifted player.c's names by -148).
Consequences:
- .strtab digit strings differ while every section's content is identical -
  PASS.
- When the counter crosses a DIGIT-COUNT boundary (@73 -> @117), strtab
  string lengths change and every later st_name OFFSET in .symtab shifts -
  the resolved-symbol view is still identical - PASS (this parked four TUs
  as false failures until the gate learned to mask it).
- Matching the counter across a large conversion is not realistically
  controllable; do not try.

**The stale-.o false-PASS hole (MANDATORY rm-first).** A failed compile
leaves the previous .o on disk, which then md5-matches the baseline. Six TUs
landed on main without ever compiling this way, and the subsequent
"totals unchanged" verification of their revert was ITSELF computed from the
stale objects - the hole recursed one level up and shifted the project
baseline by -0.00128pp fuzzy when truth surfaced. Rules: delete the TU's .o
before the gating build; assert it reappears; grep build output for
error/FAILED - never trust a piped exit code (`ninja | tail` masks failures;
this exact mistake briefly landed a broken crackanim commit).

**Report-only TUs are invisible to default ninja.** NonMatching units compile
only for the report target, not main.dol - so a shared-header change can
dirty TUs that default `ninja` + a green dol never rebuild. Gold-standard
gate for shared headers: full-build .o sweep PLUS a forced rebuild of the
complete report tree (`ninja -k 0 build/GSAE01/report.json`), error-grepped.
That forced rebuild is also what surfaces other people's latent breakage -
budget for triaging it.

**Verification evidence must be fresh.** Trusting a NINJA=0 full build
without confirming the specific TU recompiled produced a false
"byte-identical, no regression" stand-down on mmp_moonrock. rm the .o (or
check mtime) before using any object as evidence.

## 3. The shared-record registry

| Record | Header | Owner model |
|---|---|---|
| GameObject (obj head + engine tail) | include/main/game_object.h | engine |
| ObjAnimComponent (0x00-0xAF head; targetObj @0xA4) | include/main/objanim_internal.h | engine, matched header - gold gate for edits |
| CameraObject (SIBLING of GameObject) | include/main/camera_object.h | CAM partition |
| ObjPlacement (obj+0x4C common head) | include/main/obj_placement.h | engine |
| Texture | include/main/texture.h | engine |
| BaddieState / GroundBaddieState | include/main/dll/baddie_state.h | engine-wide, shared |
| TrickyState | include/main/dll/tricky_state.h | dll-a (reconciled grenade+weaponE6+collectable censuses) |
| per-family `<X>State` | include/main/dll/[<area>/]<x>_state.h | the converting partition |

Rules distilled from the registry's construction:

- **Evidence standard for shared fields** (the targetObj bar): independent
  censuses from 2+ partitions agreeing on offset/width/semantics, conflicts
  explicitly reconciled, the change landing as a standalone header-only
  commit under the gold gate, SHA announced to every consuming partition.
- **Sibling, not derived** (the CameraObject rule): when two records share a
  head but their tails assign DIFFERENT types to the same offset (camera:
  f32 fov @0xB4, f32 probePos vec3 @0xB8 vs GameObject: s16 @0xB4, extra ptr
  @0xB8), define a sibling struct and forbid cross-casting in the header
  comment. Never "extend" the wrong record because the head matched.
- **Additive-only enrichment** (the TrickyState protocol): merging a second
  TU's census into a published header may only FILL PAD REGIONS. A
  merged-majority regeneration that flips an existing field's type regresses
  every TU already converted against it (weaponE6 lesson - caught by the
  gate, reverted). Width conflicts resolve in favor of the PUBLISHED type;
  the minority TU launders (`*(u32 *)&s->field`), keeping the name visible.
  Re-gate every consuming TU (all sides) before pushing the enriched header.
- **Renames are codegen-free but not process-free**: source fn renames must
  update symbols.txt in the same commit (the moonrock rule); struct-field
  renames must update every converted reference in the same commit.
- **A TU's own prototype header is not a state header** - check existence
  before writing `include/.../<name>.h` (a state struct once overwrote a
  prototype header; new `*_state.h` filenames dodge the collision class).

## 4. Incident postmortems (3 lines each)

**mmp_moonrock (59.18 regression).** A source rename without the symbols.txt
rename orphaned a 480B fn (the big hit), and a TexScroll2Object* param retype
folded the matched addi+lwz-0 placement load (the residual). Fix: rename in
symbols.txt + restore the byte-verified int-param spellings under the new
names. Rule: symbols.txt rename in the same commit; retypes need the gate.

**emitBurst (#36 cast inflation).** An upstream retype added call-site casts
that re-weighted a register web and dropped a matched fn. Rule: casts at use
sites move allocator priorities (recipe #36) - every retype gates per-TU, and
"it is just a type change" is never exempt.

**The six-TU stale-.o chain.** Conversions referencing never-committed
structs pushed as false PASSes (stale .o md5-matched baselines), latent
because report-only TUs dodge default ninja, then the revert's own
verification measured the same stale objects - corrected baseline
95.18115/949800. Rule: rm-first gating, error-grepped builds, and totals
claims only from freshly forced report builds.
