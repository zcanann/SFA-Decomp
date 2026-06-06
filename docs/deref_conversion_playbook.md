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
     #77 family) ONLY when each converted field is referenced ONCE (or once
     per re-derivation of the base). For MULTI-USE fields on an int base,
     inline casts MATERIALIZE the field address into a register
     (`addi rX,rBase,off` + `lwz/lbz 0(rX)`, often consuming a fresh saved
     reg) where the raw int-sum folds to per-use displacement loads -
     voice_id.c (every fn) and synth_seq_dispatch.c's trackId byte are the
     evidence cases. Order of attack: typed local
     (`T *s = (T *)state;`) FIRST - it folds back to displacement loads
     byte-exact; inline casts second for single-use sites. The typed local
     can still hit the #77(d) all-or-nothing trap on high-pressure fns
     (savegpr shift) - the gate decides; revert the fn wholesale, never
     partially.
   - Member-lvalue LOAD+STORE pairs of the SAME field (read-modify across
     two statements: `v = s->f; s->f = v | K;`) CSE the field ADDRESS
     (`addi` + `stw 0(rX)`) where the raw deref pair folds both accesses to
     displacements. Keep such pairs raw (hw_init time-offset loop,
     hw_voice_params channelEntry pair). A single compound assign
     (`s->f |= K;`) is fine.
   - `(T *)(base + byteOffset)` casts on a PRECOMPUTED byte offset gate
     clean (mcmd_exec, hw_init irq loop); the equivalent
     `((T *)base)[idx].field` member-array form does NOT - it flips
     displacement stores to indexed (`stbx`, inp_midi ring) or regrows
     chain-walk fns (+12B each, synth_delay). When the source computes
     `off = idx * sizeof(T)` separately, keep that and cast the sum.
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

**Shared-record commits (rename OR adoption) gate on the FORCED report
build, error-grepped.** Default ninja + dol + per-TU gates all stay green
while a report-only consumer is broken: a BaddieState field rename and a
4-TU adoption raced on main with both sides' gates green and the forced
report build failing for the interval (fixed at aa6df9744). Standing rule:
the renamer additionally greps src/+include/ for casts/uses of the record
at PUSH time and harmonizes in the same commit if consumers appeared since
authoring.

**Chain gate -> commit -> push with && only.** A `;`-chained sequence
commits and pushes past a FAILED gate, and the dol md5 it prints comes
from stale objects - the stale-.o false-PASS hole with extra steps (the
gViewFinderFadeLevel push rode exactly this past the B29-race breakage).

**Every post-rebase push gets a FRESH forced-report gate, no exceptions.**
A gate run before `git rebase` certifies a tree that no longer exists;
the B29 BaddieState rename gated clean, then rebased over a just-landed
adoption commit and pushed broken (both sides green per the race note
above).

**Gold-gate baselines must be taken AFTER a forced report build.** A
default-ninja tree holds stale report-only objects (NonMatching TUs dirtied
by earlier upstream commits but never rebuilt), so a full-tree .o md5
baseline taken from it attributes other people's pending recompiles to YOUR
header change (~30 phantom diffs from one upstream rename sweep). Force
`ninja build/GSAE01/report.json` first, then baseline, then edit.

**Verification evidence must be fresh.** Trusting a NINJA=0 full build
without confirming the specific TU recompiled produced a false
"byte-identical, no regression" stand-down on mmp_moonrock. rm the .o (or
check mtime) before using any object as evidence.

**Comments must be PURE ASCII (team style rule).** Everything compiles
through sjiswrap; UTF-8 punctuation (em-dashes, arrows, typographic
quotes, <=/>=/identical-to glyphs, superscripts) is invalid Shift-JIS and
triggers encoding warnings that can escalate to hard errors. Write "--"
not an em-dash, "->" not an arrow glyph, straight quotes, "^2" not a
superscript. The gate's rebuild grep also flags "encoding" lines.

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
- **MWCC 2.0 8-aligns a real `u64` member - MP4 audio struct transplants
  with mid-struct u64 fields will NOT reproduce the layout.** MP4's
  SYNTH_VOICE declares `u64 cFlags` at 0x114 (4-mod-8); declaring the same
  in SFA pushes it to 0x118 and fails the offsetof STATIC_ASSERT. Declare
  `u32 cFlags[2];` at the true offset and spell u64-wide accesses as
  `*(u64 *)&s->cFlags` launders (sub-word halves are `cFlags[0]`/`[1]`,
  big-endian: [0]=high). synth_voice.h is the evidence case. Always
  STATIC_ASSERT offsets when transplanting MP4 shapes - the assert catches
  this class at compile time.

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
