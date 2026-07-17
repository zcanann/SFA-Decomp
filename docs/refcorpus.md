# Reference-asm corpus (`tools/refcorpus/`)

A searchable corpus of **GC/2.0-emitted** PowerPC assembly, produced by recompiling real,
SFA-adjacent reference-decomp C with *our* compiler (MWCC GC/2.0) and *our* flags.

It answers the playbook question — "what C produces this asm shape, under our compiler?" —
with real examples instead of guesswork. Unlike grepping a reference project's own committed
asm, every sample here is the shape **GC/2.0** emits, across the exact peephole/scheduling
profiles SFA toggles. We are **not** byte-matching the reference binaries; the immediates and
addresses are meaningless. Only the *instruction shapes* matter.

## What's in it

| project | source | why it's here | yield (funcs/profile) |
|---------|--------|---------------|-----------------------|
| `melee` | Super Smash Bros. Melee (GC, MWCC C) | 2001 game/HAL engine code; broad C89-era control-flow corpus | 19,383 |
| `mp4` | Mario Party 4 (GC, MWCC C) | same console/compiler/era as SFA | 10,383 |
| `mp4_musyx` | MP4 MusyX 1.5.4 runtime (GC, MWCC C) | directly relevant to SFA's MusyX audio recovery | 602 |
| `mp4_msm` | MP4 MSM audio manager (GC, MWCC C) | game-side examples built on the same MusyX API | 95 |
| `dkr` | Diddy Kong Racing (N64, C) | SFA's engine descends from it — shared source | 853 |
| `jfg` | Jet Force Gemini (N64, C) | modified DKR engine, shares SFA code | 288 (early-stage decomp) |

Each source unit is compiled in **four profiles** — the peephole × scheduling matrix SFA uses
(`both_off` is SFA's global default, turned on per-function via `#pragma` in real source):

| profile | `-opt` flags |
|---------|--------------|
| `both_off` | `nopeephole,noschedule` |
| `peep_on`  | `peephole,noschedule` |
| `sched_on` | `nopeephole,schedule` |
| `both_on`  | `peephole,schedule` |

The measured corpus is **126,416 function-asm samples** (31,604 functions/profile). Output
lives under `build/refcorpus/` (gitignored); reference clones live under
`reference_projects/` (also gitignored).

## Get the sources

`reference_projects/` is gitignored, so a fresh checkout has none of them and the corpus
searches 0 funcs until they are cloned. Clone all four, then build:

```bash
mkdir -p reference_projects
git clone --recurse-submodules https://github.com/mariopartyrd/marioparty4 \
  reference_projects/marioparty4
git clone https://github.com/DavidSM64/Diddy-Kong-Racing     reference_projects/dkr
git clone https://github.com/Ryan-Myers/Jet-Force-Gemini     reference_projects/jfg
git clone https://github.com/doldecomp/melee                  reference_projects/melee
```

`--depth 1` is fine; only the working tree is read. If MP4 was already cloned without its
submodules, run `git -C reference_projects/marioparty4 submodule update --init --depth 1`.
The dir names are the `root` fields in `recipes.py` and must match. No ROM or upstream
toolchain is needed — we compile with our own MWCC GC/2.0, and generated opaque definitions
preserve the exact size/alignment of the few disc-extracted arrays referenced by code-bearing
units.

## Build

```bash
python3 tools/refcorpus/build_corpus.py                 # all projects, all profiles
python3 tools/refcorpus/build_corpus.py --projects dkr  # one project (merges into manifest)
python3 tools/refcorpus/build_corpus.py --jobs 8 --force # rebuild ignoring the hash cache
python3 tools/refcorpus/build_corpus.py --list-fails     # per-project failure-reason histogram
```

Best-effort: a unit MWCC GC/2.0 won't accept is logged in `build/refcorpus/coverage.json` and
skipped, never fatal. Results are cached by `(source, flags, shim/stub)` hash, so reruns are
incremental. Coverage separates code-bearing, zero-function, and failed units rather than treating
placeholder objects as useful yield. `build/refcorpus/manifest.json` lists every produced `.s`
and its original C source.

## Search

```bash
# asm shape -> compact matching-function list
python3 tools/refcorpus/search_corpus.py --asm 'rlwinm r[0-9]+,r[0-9]+,0,.*,'

# instructions in order (gaps allowed)
python3 tools/refcorpus/search_corpus.py --seq 'extsb. rlwimi'

# the reverse: find compiled functions containing matching reference C
python3 tools/refcorpus/search_corpus.py --csrc '&= ~0x80' --profile both_on

# inspect one selected function's complete GC/2.0 assembly and original C
python3 tools/refcorpus/search_corpus.py --show rc_0123456789ab

# scoping / sizing
python3 tools/refcorpus/search_corpus.py --asm 'psq_l' --project dkr --limit 20
python3 tools/refcorpus/search_corpus.py --stats
```

`--profile` defaults to `both_off` (SFA's default); pass `all` to search every profile.
Discovery output contains only a stable result ID, instruction count, match span, project,
profile, function name, and source path. Results are sorted by instruction count ascending,
so small self-contained examples appear first. Use `--show ID` only after choosing a useful
candidate; it prints that function's complete normalized assembly and original C. IDs are
derived from project/profile/source/symbol and remain stable across corpus rebuilds.

`--asm` is a regex over the whole function's normalized text, so `\n` matches across
instructions and backreferences can tie a register across lines — that is how you pin a
shape rather than a mnemonic:

```bash
# an address add whose result is used at a displacement, while the same base+index
# is also used indexed -- \1 \2 \3 tie the registers together
python3 tools/refcorpus/search_corpus.py \
  --asm '(?m)^add r(\d+),r(\d+),r(\d+)\n\w+ r\d+,\d+\(r\1\)\n\w+x f?\d+,r\2,r\3'
```

## Target symbol context

The read-only symbol explorer avoids broad searches through a generated `.ctx` or the whole
source tree. An isolated harness workspace supplies target metadata automatically:

```bash
python3 tools/symbol_context.py relevant
python3 tools/symbol_context.py get ModelLightStruct
```

`relevant` extracts the target function, lists its direct and transitively referenced
compound/layout types, reports the defining file, and distinguishes full definitions from
forward declarations in that target's exact `.ctx`. `get` returns one complete balanced
struct/union/enum/typedef declaration. Conflicting definitions are never selected silently;
the command reports the candidate paths and accepts `--path` to disambiguate.

Outside a harness workspace, supply the target explicitly:

```bash
python3 tools/symbol_context.py relevant \
  --source src/main/track_dolphin.c \
  --function queueGlowRender \
  --context build/GSAE01/src/main/track_dolphin.ctx
python3 tools/symbol_context.py get ModelLightStruct \
  --context build/GSAE01/src/main/track_dolphin.ctx
```

Findings that came out of the corpus (each traced to a named reference function):

- **Element-address addressing** (`dkr audspat_play_sound_at_position`, `dkr
  catmull_rom_interpolation`, `mp4 GetLinear`). For a uniform typed `arr[idx].field`
  spelling, GC/2.0 loads the **offset-0 field with the indexed form** (`lfsx`/`lhzx`/`lwzx`
  off base+index) and every **nonzero offset as a displacement off a single `add`**. The
  `add` materializes at the **first nonzero-offset use** -- interleaved with call-argument
  marshalling, not hoisted to the statement head. An argument spelled with raw `u8*`
  arithmetic sits outside that typed tree and keeps its own indexed load.
- **Unfolded `beq X; b Y`** (`mp4 HuAR_DVDtoARAM`, `dkr get_lockup_status`). An early-return
  guard whose `return` yields a **value** leaves the pair unfolded, because the then-block is
  real code placed after the fallthrough. A bare `return;` (void) makes the then-block the
  epilogue itself and GC/2.0 always folds it to a single conditional -- no source spelling
  tested recovers the pair in that case.
- **Ternary → unfolded branch pair** (`dkr audspat_reverb_get_strength_at_point`, via its
  `ABS2` macro). `(x >= 0) ? x : -x` emits the branch-over-branch pair plus a negate, rather
  than a folded conditional.

## How it works / caveats

- **Base flags** = SFA's exact main-lib flags from `build.ninja`
  (`-nodefaults -proc gekko -align powerpc -enum int -fp hardware -O4,p -inline auto … -lang=c`),
  with only the `-opt` peephole/scheduling axis varied per profile.
- **Project semantics stay local to recipes.** Native source assumptions such as unsigned
  `char`, DKR's matching-build `ANTI_TAMPER`/CIC/SRAM defines, and IDO's permissive
  pointer-to-pointer conversions are enabled per project. MP4's one pooled-data outlier uses
  its native `-pool off`. MusyX is a separate recipe family with its native 1.5.4 target
  defines, hard-FP/string-pool semantics, and FP contraction disabled; MSM remains a separate
  signed-char family. These do not replace SFA's O4 or the four optimization profiles.
- **N64 shim** (`shims/n64_mwcc.h`, force-included via MWCC `-prefix`): neutralizes GCC/IDO-isms
  MWCC rejects (`__attribute__`, `__builtin_va_*`, `GLOBAL_ASM`, GCC keyword spellings). The N64
  sources also need `-D_LANGUAGE_C` and `-char unsigned`.
- **Generated headers**: N64 decomps include ROM-generated identifiers (`asset_enums.h`), so
  `recipes.py` auto-harvests them. MP4's source-only checkout omits extracted `.inc` arrays;
  its config supplies the exact header-to-symbol mapping, while `symbols.txt` supplies each
  object's exact size and alignment. The generator emits zero-filled opaque arrays with that
  metadata intact, preventing accidental SDA placement. Those arrays are only addressed/indexed
  at runtime—never used by `sizeof` or in compile-time control flow—so their unavailable byte
  contents cannot change function instruction shape.
  Generated files live under `build/refcorpus/gen/<project>/` and are never committed.
- **C89 and include compatibility**: GC/2.0 compiles C with the project headers; imported sources
  are never rewritten. Melee's C already targets an older MWCC dialect, but contains many
  ambiguous sibling includes such as `"types.h"`. Its recipe enables `include_source_dir`, which
  prepends each input file's own directory to MWCC's include search. Without that conservative
  adjustment GC/2.0 silently selected unrelated headers; it also fixes JFG's bare local
  `math.h`. Narrow generated source copies handle one DKR C99 loop declaration and explicit
  32-bit IDO pointer conversions; the imported clones remain untouched and searches still show
  their original C. New syntax should otherwise be skipped and logged rather than broadly
  rewritten.
- **Coverage describes eligible translation units.** MP4 is 333/333 and Melee 915/915. DKR is
  36/45: its nine remaining units all hit GC/2.0's stricter nested aggregate initialization, so
  they remain honest best-effort skips. JFG is 207/207, but 174 successful units currently contain
  only `GLOBAL_ASM` placeholders and therefore add no functions; kiosk-only wrong-version
  placeholders and its target-MIPS stack-pointer intrinsic are excluded. MusyX is 31/31 (29
  code-bearing plus two data-only units), and MSM is 6/6 with all six code-bearing. Upstream C
  improvements automatically increase yield on rebuild.
- **Inventory avoids false translation units.** Overlapping MP4 globs are de-duplicated. DKR's
  USB children compile through their real `debug.c` unity unit, not again standalone. MP4's
  include-only `REL/executor.c` is likewise not compiled standalone; its `_prolog`/`_epilog`
  naturally remain in each REL that includes them. SDK/runtime/TRK and data-only files are omitted
  where they add no useful function shapes.

## Adding a project

Add one `Recipe` to `tools/refcorpus/recipes.py` (include dirs, defines, globs, recipe-wide
`extra_flags`, and whether it needs the N64 shim / a stub generator), clone it under
`reference_projects/`, and rebuild. Prefer project/header configuration over source rewriting.
Use `include_source_dir=True` for projects with many ambiguous quoted sibling headers. E.g.
Mickey's Speedway USA — another Rare N64 title SFA borrowed from — is a one-entry add once a
decomp exists.
