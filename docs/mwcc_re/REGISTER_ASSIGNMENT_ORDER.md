# Register-assignment order — the meta-root of the coloring caps

**Question.** Roughly a dozen banked caps share one symptom: our build assigns physical
registers in the **reverse** order retail did, for three recurring shapes —

- **(a) CSE'd conversion-magic / FP constants** — retail gives the magic the *higher*
  freg, the product the *lower*; ours reversed (`at-nnn-conversion-bias`, camTalk
  `CameraModeBike_update` f2↔f3).
- **(b) spilled accumulators / computed products** — retail reuses the source reg in place,
  ours takes a fresh higher reg (`computed-fresh-reg-crux`, dll_0042 `camslide_update` f0↔f2).
- **(c) param homes / later-born webs** — retail: earlier-declared → higher saved reg;
  ours: a later-born web outranks it (`ascending anomaly`, dll_0044
  `CameraModeViewfinder_update` r30↔r31).

Is this reverse ordering a **compiler-version or -flag artifact** (⇒ config-fixable, would
unlock all three shapes at once) or **irreducible from config**?

## Verdict: IRREDUCIBLE FROM CONFIG — it is source-context (web-creation-order) dependent.

No compiler point release and no flag changes the coloring. The register a web receives is a
deterministic function of exactly two inputs — the **interference graph** and the **web
index** (order of value creation in the IR) — and *neither is a compiler knob*. The three
shapes are **one root**: our recovered C introduces the competing values into the IR in a
different order than the original C did, so the fixed allocator colors them differently.

All three capped functions are otherwise **structurally byte-identical** to retail (same
instruction count, same opcodes, same operands) — every single divergence is a register
*name* swap. `CameraModeViewfinder_update`: 314/363 instrs identical, the other 49 are pure
r30↔r31 / r29↔r31 renames. Same story for the other two. Nothing but coloring is at stake.

## Evidence

### 1. The allocator has no flag input (static recovery)
`docs/mwcc_re/recovered/Coloring.c` (band `0x508680–0x509010`) is a textbook Chaitin–Briggs
allocator:

- **Simplify** (`0x508a20`): remove low-degree webs in **web-index (creation) order**, push
  on a stack; when stuck, optimistic-spill the parked web with min `degree/cost` — but `cost`
  (`web+0xc`) is bzero'd and **never written**, so the ratio is `+Inf` for every web and the
  search never updates: it just removes the **highest-index** parked web. Selection is purely
  **structural (web index)**, never cost-weighted.
- **Select** (`0x508900`): pop the stack, give each web the **lowest free** physical register
  not used by an interfering neighbor.
- **Coalesce** (`0x508c10`): merge copy src/dst webs by identity; eligibility flags are set
  **upstream** during web/move building, not by any command-line switch.

The only two things this reads are the interference graph and `web->index`. There is no
`-opt` sub-flag, no priority knob, no coalesce/spill switch anywhere in the pass.

### 2. Compiler-version sweep — none flips it
`CameraModeViewfinder_update`, real cflags (`-O4,p -opt nopeephole,noschedule`), the `this`
param's home register across every GC point release:

| version | `mr this` | | version | `mr this` |
|---|---|---|---|---|
| GC/1.2.5  | r28 | | GC/2.0    | **r30** |
| GC/1.2.5n | r28 | | GC/2.0p1  | **r30** |
| GC/1.3    | r30 | | GC/2.5    | **r30** |
| GC/1.3.2  | r30 | | GC/2.6/2.7| **r30** |
|           |     | | GC/3.0a3/a5 | **r30** |

Retail is **r31**. No version produces it. (1.2.5/1.2.5n give r28 — a different, older
allocation entirely, and are the wrong compiler for this TU regardless.)

### 3. Flag sweep under GC/2.0 — none flips it
Every one of these produced `this→r30` (retail wants r31), identical to baseline:
`-opt {nocse, nolifetimes, nopropagation, nostrength, noloop, nodeadcode, nodeadstore,
nodead, level=2}`; `-inline {off,none,all,deferred}`; `-char {signed,unsigned}`;
`-fp {fmadd}`, `-fp_contract off`; `-use_lmw_stmw {on,off}`; `-common {on,off}`; `-sym on`;
`-rostr`; `-str reuse,pool,readonly`; `-enum min`; `-schedule on`.
(`-opt off` / `-opt level=0` *do* print r31 — but they disable the allocator entirely and
emit a completely different, unoptimized 388-instr function: 19/363 match. Meaningless.)
`mwcceppc.exe --help` exposes **no** register-allocation-ordering, coalescing, or
spill-priority flag; `-opt level=n` is the only allocation knob and levels 0–4 were all tried.

### 4. The refcorpus proves forward order IS achievable with our exact toolchain
`tools/refcorpus/` recompiles SFA-adjacent reference C with **our GC/2.0 + our flags**. In the
`both_off` profile (= `-opt nopeephole,noschedule`, exactly SFA's `cflags_dll_noopt`):

```
$ python3 tools/refcorpus/search_corpus.py --asm 'mr r31, ?r3'
[1289 hit(s) over 9740 funcs; profile(s): both_off]
  mp4/both_off  ClusterMotionExec(ModelData *arg0):  mr r31,r3 ; mr r30,r3 ; ...
```

**1289** functions get forward-order param→r31 under the *same compiler and flags* that give
our capped functions reverse order. Same toolchain emits **both** orders depending only on the
function. That is the definition of source-context-dependence, and it flatly rules out a
global config fix: if a flag were responsible, it could not be right for 1289 funcs and wrong
for these three simultaneously.

### 5. Source order visibly moves the coloring
Splitting one statement of `CameraModeBike_update` into a named temp (changing IR creation
order) shifted register assignment and scheduling at the edited site — direct confirmation the
allocator responds to source structure, not just flags.

### 6. Independently confirmed by the dynamic Select validation
`VALIDATION.md` reached the same conclusion from the other direction: on two byte-identical
real compiles the decompiled `Select` predicted **87/87 + 63/63** volatile choices and **22/22**
saved-register fallbacks exactly, each function handing out `r31, r30, r29 …` **descending in
coloring order**. Its own summary: *"Which saved register ⟺ the order webs hit the fallback,
which follows web creation/coloring order ⟹ the decl/first-use-order lever. **No knob — a real
lifetime change.**"* This investigation adds the missing negative half: the exhaustive
version+flag sweep that proves no knob exists, and the refcorpus same-toolchain-both-orders
proof.

## Consequence for the frontier

Every "reverse register order" cap is a **source web-ordering problem**, reachable only
through the web-order levers already in the playbook (first-def web indexing; decl-order sets
saved-reg homes; unfuse-product temps / dedicated-product local for FP frA; const-before-base;
comma-init emission order; sink/hoist base locals; etc.), **never** a `configure.py` change.
There is no compiler switch to find. An unsolved one is a not-yet-found source shape, not a
config gap.

Direction is **not** a simple constant (a minimal 2-param repro colored the earlier param
r28 and the later r29 — ascending — while `ClusterMotionExec`'s param takes r31): it is the
joint outcome of the interference graph and Simplify-pop order, i.e. genuinely per-function.
This is *why* it never reduced to a flag.

### Also explains
- The `@NNN`-vs-`lbl_803Exxxx` reloc-name differences seen **alongside** these swaps are a
  **separate** issue (`.sdata2` pool symbol naming / claim order), not coloring — do not
  conflate them when reading an ndiff of a capped coloring function.

## Reproduce
```
cflags = -O4,p -opt nopeephole,noschedule  (GC/2.0, per cflags_dll_noopt)
# version sweep:  for V in 1.2.5 … 3.0a5; do compile dll_0044; disasm; grep 'mr …,r3'; done
# flag sweep:     same unit, append each -opt/-inline/-char/... ; all give r30
# corpus:         python3 tools/refcorpus/search_corpus.py --asm 'mr r31, ?r3'  → 1289 both_off
```
