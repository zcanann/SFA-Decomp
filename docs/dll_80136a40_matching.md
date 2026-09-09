# dll_80136a40 (debug display) — residual analysis

## Current frontier (2026-09-07)

The current TU uses GC/1.3 with `-opt nopeephole,noschedule`; strength reduction
is enabled. After shared unsigned pixel writes and separator cursor recovery,
11/14 functions and all assigned data match exactly, with 99.76295% TU fuzzy.
See [the recovery record](debug_font_error_data.md) for validation across EN,
EN revision 1, JP, and PAL revision 1.

| Function | Similarity | Retail / source instructions |
| --- | ---: | ---: |
| `debugPrintDrawRecord` | 99.90131% | 456 / 456 |
| `debugTextDrawToFrameBuffer` | 97.65625% | 96 / 96 |
| `errorThreadFunc` | 99.71614% | 694 / 694 |

The crash thread now has no structural differences. Its 35 differing words
exchange the cached font-block and self-address registers, apart from two
vertical-rule initializations emitted in reverse order. A scalar local for the
diagnostic self-address fixes that register exchange but introduces an extra
copy; it is not retained. Inlining a font-data view at each use instead of
caching the view worsens the instruction stream and is also not retained.

The record decoder has nine differing words: the wrap rectangle exchanges
`r24` and `r25` for its top and right coordinates. Reordering the shared helper's
coordinate declarations either worsens this or also regresses the exact
`debugPrintDraw`. Separate X/Y scale locals and an explicit wrap-scale local
leave the result unchanged.

**Inspect callers before accepting a raster improvement.** Before the unsigned
pixel writer, a paired-scanline inline helper with an indexed five-row caller
raised the rasterizer alone to 87.09375% (95 instructions). It also made MWCC
inline the rasterizer into
`debugPrintfxy`, losing that exact function and reducing whole-TU similarity
from 94.26345% to 89.16091%. Expanding that row body directly into the glyph loop
preserved the formatter's calls but scored only 79.03125% for the rasterizer.
Neither variant is retained. Further recovery must account for the compiler's
inlining decisions as well as its induction variables and register allocation.

## Historical measurements with strength reduction disabled

The remainder records the earlier `nostrength` experiment. Its residual counts
and closed probe conclusions are specific to that profile, not the current
source or compiler settings.

Unit `main/dll_80136a40.c`, GC/1.3, `-opt nopeephole,noschedule,nostrength`. Four functions
remain below 100%, 27 differing instruction words in total; every other function and every
data section is byte-exact. All findings below were measured with the GC/1.3 dump-hook tracer,
which now runs on Linux (`tools/mwcc_backend_capture_gdb.py`, see [tools](#tooling)).

| function | words | residual |
|---|---|---|
| `debugTextDrawToFrameBuffer` | 7 | `x`/`row1` saved-register exchange (r29/r27) and the `mr r26,r5` glyph-pointer copy two slots early |
| `debugPrintDrawRecord` | 17 | in all three rect blocks the unconverted `x0` lives in r25/r23 (saved) in retail but in r5 (scratch) here |
| `debugPrintfxy` | 2 | retail materialises `text - 1` twice (`addi r26,r1,115; addi r27,r1,115`), we emit one `addi` and an `mr` |
| `errorThreadFunc` | 2 | `rows = y + 0x4c` sits after the hoisted `0xc080` constant in the loop preheader in retail, before it here |

Flag and version probes are closed: every `-opt` sub-flag, `-O2..-O4,{p,s}` and compiler versions
1.2.5 through 2.7 either leave the four unchanged or regress the whole unit (`fn_flag_probe.py`
agrees). The residuals are source-shape problems.

## GC/1.3 backend facts established here

These were read from captured IR and replayed colouring graphs, not inferred from bytes.

**Virtual-register numbering.** Parameters take 32, 33, … in declaration order (an unreferenced
parameter takes no number). Locals are numbered *after* the parameters in **reverse declaration
order** (the first-declared local has the highest number). Frontend temporaries follow in program
order. A variable version created by the frontend's renaming takes a number in **reverse
first-definition order** of the renamed variables. Induction variables created by strength
reduction take fresh numbers above everything else.

**Simplification and colouring.** The allocator sweeps registers 32…N in ascending order,
removing every node whose current degree is below the 29 available GPRs (r0, r3–r12, r14–r31),
decrementing neighbours as it goes, and repeats until nothing is removable; colouring order is
the reverse of removal. A web is coloured from the saved bank (r31 downward, highest free) only
when it interferes with the call-clobbered physical registers r3–r12, i.e. when it is live across
a call, or when its scratch bank is exhausted; otherwise it takes the lowest free scratch register
(r0 only for degree-0 webs). Consequences:

- Among the call-crossing webs, the first-declared local gets r31, the second r30, and so on.
- A parameter is visited first in every sweep, so it is always the **last** call-crossing web
  coloured, i.e. it takes the lowest saved register of that group. Copying a parameter into a local
  never helps: the frontend folds a plain copy at the tree level, and the backend's copy
  propagation folds every other spelling tried (initialiser, dead redefinition of either side,
  inline wrapper, K&R declaration, `register`).
- A short-lived web can only reach the saved bank if its number is above the loop's temporaries,
  which is true only for induction variables created by strength reduction.

**Frontend renaming.** For a variable with exactly two versions, `v = v * e` renames the *new*
value (the old one keeps the variable's number) and `v *= e` renames the *old* value. A variable
with a conditional redefinition (a merge, e.g. `if (x0 >= 2) x0 -= 2;`) is never split. The
parameter redefinition `x = y + 1` is renamed into a temporary, so the parameter web survives.

**Pass order and placement.** Value numbering runs before constant propagation and merges
identical frame-address computations into one `mr`; copy propagation folds `p = text; p--;`
into `text - 1` before strength reduction; the strength-reduction stage (still present under
`nostrength`) merges two lockstep induction variables whose initialisations are identical
instructions, and only skips that when one init is a copy of the other. Alias propagation inserts
an empty preheader block; code motion appends hoisted invariants to it; strength reduction appends
its induction-variable initialisations after them (a `grid + i` pointer IV lands at the end of the
preheader, an `i * K` IV right after the counter's own `i = 0`); the unroller appends the
trip-count guard last. Under this profile strength reduction reduces subscript scaling of source
induction variables, `ptr[i]` loads (base folded into the init) and `i * K` for the primary
counter (init 0); it does not fold an invariant base into an integer induction variable and does
not reduce products of secondary counters.

## What the retail objects require

`debugTextDrawToFrameBuffer`: retail colours c1 r31, i r30, x r29, row0 r28, row1 r27, p r26,
bit r25, and emits `li r30,0; addi r0,r4,1; mr r26,r5; mulli r27,r0,640; mulli r28,r4,640`.
Under the policy above the parameter can only sit at r29 if `row0`, `row1` and `p` are all
low-degree when swept, i.e. compiler-created induction variables numbered after the glyph pointer
IV, with `y + 1` hoisted ahead of their inits. That layout was reproduced exactly by making `x` a
non-foldable local (a model test only). No integer expression of `y` and `i` produced such rows
under `nostrength`: `(y + 2*i) * 0x280`, `y*0x280 + i*0x500`, a line counter stepping by two
(secondary or primary), pointer-typed rows and 2-D row types all keep the multiply in the loop or
add the invariant per iteration. `y1 = y + 1; p = grid;` locals reproduce the copy placement but
make `p` a named local coloured before `x`.

`debugPrintDrawRecord`: the unconverted `x0` in each rect block dies at its float conversion
without crossing a call, yet retail gives it the same saved register as the converted value. The
full spelling space for blocks 1 and 2 (120 declaration orders × 2 load orders × compound/plain
conversion per variable × 2 conditional forms) bottoms out at the current text. Making the five
rect locals function-scope temporaries shared across the blocks brings blocks 2 and 3 to
byte-exact but leaves block 1 (the first textual definition) unchanged; reusing those temporaries
as the colour bytes of cases 0x81/0x85 does not fix block 1 either. Reading `gDebugRectStartX`
directly in the condition makes the value a scratch temporary and adds a copy.

`debugPrintfxy`: the two `addi r,r1,115` survive only if the second is not the same expression
at value-numbering time and its induction variable is not merged at strength reduction, then folds
to the same address afterwards. Every plain-C spelling tried (separate statements, `text; --`,
mixed `char*`/`u8*`, an offset variable assigned in another block or from a call result, index
loops `s[++i]`, one pointer moved before `vsprintf`) is merged by one of those passes; index loops
stay indexed under this profile.

`errorThreadFunc`: `rows = y + 0x4c` is emitted at its statement position in every spelling
(statement, `for` init, `rows-- >`, `do`/`while`, reused `n`, inline helper); count-up
loops and invariant-in-condition loops change the unroll shape or are not unrolled. In retail the
init sits after the hoisted constant and before the unroller's guard, which is where strength
reduction appends induction-variable inits.

## Tooling

The GC/1.3 backend tracer (`tools/tricky_backend_trace.py`) now has a Linux provider,
`tools/mwcc_backend_capture_gdb.py`: it runs the compiler under gdb through wibo, waits for the
PE image via `catch syscall mmap`, breakpoints the disabled dump hook and the two colouring-graph
entry sites, and emulates the patched instructions. The object produced under the debugger must
equal the ordinary compile, as on the other platforms. Example:

```sh
python3 tools/tricky_backend_trace.py --unit main/main/dll_80136a40 \
    --function debugTextDrawToFrameBuffer --graph --register 32
```

`--read <trace.json>` then replays the colouring without a debugger. `pyelftools` and a gdb with
Python support are required.
