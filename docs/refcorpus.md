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
| `mp4` | Mario Party 4 (GC, MWCC C) | same console/compiler/era as SFA | ~9.7k |
| `dkr` | Diddy Kong Racing (N64, C) | SFA's engine descends from it — shared source | ~590 |
| `jfg` | Jet Force Gemini (N64, C) | modified DKR engine, shares SFA code | ~190 (early-stage decomp) |

Each source unit is compiled in **four profiles** — the peephole × scheduling matrix SFA uses
(`both_off` is SFA's global default, turned on per-function via `#pragma` in real source):

| profile | `-opt` flags |
|---------|--------------|
| `both_off` | `nopeephole,noschedule` |
| `peep_on`  | `peephole,noschedule` |
| `sched_on` | `nopeephole,schedule` |
| `both_on`  | `peephole,schedule` |

Total ≈ **42k function-asm samples**. Output lives under `build/refcorpus/` (gitignored, ~250M);
the reference clones live under `reference_projects/{dkr,jfg}` (also gitignored).

## Get the sources

`reference_projects/` is gitignored, so a fresh checkout has none of them and the corpus
searches 0 funcs until they are cloned. Clone all three, then build:

```bash
mkdir -p reference_projects
git clone https://github.com/mariopartyrd/marioparty4        reference_projects/marioparty4
git clone https://github.com/DavidSM64/Diddy-Kong-Racing     reference_projects/dkr
git clone https://github.com/Ryan-Myers/Jet-Force-Gemini     reference_projects/jfg
```

`--depth 1` is fine; only the working tree is read. The dir names are the `root` fields in
`recipes.py` and must match. No ROM or upstream toolchain is needed — we compile with our own
MWCC GC/2.0, and the stub generators cover the ROM-derived headers.

## Build

```bash
python3 tools/refcorpus/build_corpus.py                 # all projects, all profiles
python3 tools/refcorpus/build_corpus.py --projects dkr  # one project (merges into manifest)
python3 tools/refcorpus/build_corpus.py --jobs 8 --force # rebuild ignoring the hash cache
python3 tools/refcorpus/build_corpus.py --list-fails     # per-project failure-reason histogram
```

Best-effort: a unit MWCC GC/2.0 won't accept is logged in `build/refcorpus/coverage.json` and
skipped, never fatal. Results are cached by `(source, flags, shim/stub)` hash, so reruns are
incremental. `build/refcorpus/manifest.json` lists every produced `.s` and its C source.

## Search

```bash
# asm shape -> the C that emits it (regex over normalized "mnemonic operands" text)
python3 tools/refcorpus/search_corpus.py --asm 'rlwinm r[0-9]+,r[0-9]+,0,.*,' --show-c

# instructions in order (gaps allowed)
python3 tools/refcorpus/search_corpus.py --seq 'extsb. rlwimi'

# the reverse: grep the reference C, show the GC/2.0 asm it produced
python3 tools/refcorpus/search_corpus.py --csrc '&= ~0x80' --profile both_on

# scoping / sizing
python3 tools/refcorpus/search_corpus.py --asm 'psq_l'  --project dkr --limit 20 --context 5
python3 tools/refcorpus/search_corpus.py --stats
```

`--profile` defaults to `both_off` (SFA's default); pass `all` to search every profile.
Symbols in the corpus equal the C function names (MWCC doesn't mangle C), so `--show-c` and
`--csrc` can round-trip between asm and source.

## How it works / caveats

- **Base flags** = SFA's exact main-lib flags from `build.ninja`
  (`-nodefaults -proc gekko -align powerpc -enum int -fp hardware -O4,p -inline auto … -lang=c`),
  with only the `-opt` peephole/scheduling axis varied per profile.
- **N64 shim** (`shims/n64_mwcc.h`, force-included via MWCC `-prefix`): neutralizes GCC/IDO-isms
  MWCC rejects (`__attribute__`, `__builtin_va_*`, `GLOBAL_ASM`, GCC keyword spellings). The N64
  sources also need `-D_LANGUAGE_C` and `-char unsigned`.
- **Stub headers**: N64 decomps include headers generated from the ROM (`asset_enums.h`). We don't
  have the ROM, so `recipes.py` auto-harvests the referenced identifiers and emits a stub under
  `build/refcorpus/gen/<project>/`. Values are not rom-accurate — irrelevant for a shape corpus.
- **Coverage is partial by design.** DKR ~74% of units compile (the rest hit genuine MWCC-2.0
  initializer strictness — nested brace elision — which isn't shimmable). JFG compiles ~97% of
  units but many are still `GLOBAL_ASM` stubs, so its function yield is low today and grows as the
  upstream decomp progresses. Re-clone + rebuild to pick up upstream progress.

## Adding a project

Add one `Recipe` to `tools/refcorpus/recipes.py` (include dirs, defines, globs, whether it needs
the N64 shim / a stub generator), clone it under `reference_projects/`, and rebuild. E.g. Mickey's
Speedway USA — another Rare N64 title SFA borrowed from — is a one-entry add once a decomp exists.
