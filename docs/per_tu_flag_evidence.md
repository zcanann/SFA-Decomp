# Per-TU compiler-flag evidence

**This is an evidence file, not a proposal.** Nothing here recommends a `configure.py` change.
Per `CLAUDE.md`, pragmas may only be configured at the TU level via `configure.py` cflags, a
DOL-confirmed TU must never be split for match percentage, and only DOL section / pool /
function-order / source-tag evidence may redraw a boundary. Every row below is recorded so that
whoever holds that adjudication has the measurements in one place instead of scattered across
three lanes' notes.

## GC/1.3 revalidation — 2026-09-07

The closed-sweep conclusions below describe the earlier compiler configurations; they do not
establish the same result under the common GC/1.3 game compiler. Rebuilding the complete
`main/gameloop_buttonobj.c` TU from its current Ninja compiler command with only
`-opt nopeephole` added produces **100%** in objdiff: both functions and all 236 text bytes match.
The configured baseline was 98.22034%, with `removeButtonObject` at 98.09091% and
`getButtonObjects` already exact. Retail retains `srwi r0,r3,3; cmplwi r0,0`; peephole optimization
fuses those into `srwi. r0,r3,3` and shortens the function by four bytes.

The TU now uses the existing `cflags_dll_noopt_noautoinline` profile and is matching for GSAE01.
This preserves GC/1.3, `noschedule`, `-inline noauto`, the source, and the existing TU boundary.
It supersedes row 4's earlier negative result; no compiler-version exception is needed.
Validation: `python3 configure.py --matching`, `ninja all_source`, and the strict `ninja` retail
checksum target pass with this TU linked from C. Clang-format checks pass for the TU and its
shared game-loop headers; formatting leaves the source and object unchanged.

## Why this file exists

Working the narrow-band frontier (`tools/bandscreen.py --max-band 3 --struct-only`, the regime
where the register-band assignment is predictable and structure is the only free variable),
**four of five `regB == 0` chases resolved to compiler configuration rather than source shape.**
That is a different kind of residual from the ones the project normally fixes, and it is not
actionable from a lane. The pattern is worth adjudicating as a whole rather than one function at
a time.

## Historical sweep: the flag axis was closed for the measured configurations

**89 of 89 units carrying sub-100 functions have been swept across the pair and triple `-opt`
space. Zero candidates.** A candidate meant: strictly more byte-identical functions than the
unit's baseline, with **zero** function regressions. Nothing anywhere passed.

| sweep | units | probes | distinct outputs | candidates |
|---|---|---|---|---|
| pairs+triples, 8 GC/2.0 tokens toggled from configured state | 82 | 7,476 | 2,361 (**68.4% absorption**) | 0 |
| re-sweep over censused live tokens (the 7 below) | 3 | 80 | 62 | 0 |
| units with a single live token — **combination space is empty** | 4 | — | — | n/a |

This sits on top of w81's single-knob sweep (153 units × 8 tokens, 11 pure wins, exhausted) and
`fn_flag_probe`'s nine fixed profiles. Singles, fixed pairs, and now the full pair/triple
interaction space are all exhausted. **86 of 89 units contain combinations that flip some function
to byte-identical — and every one costs more elsewhere than it buys**, which is the `subtitle`
precedent (`level=1` dominance; 100.000 bought at 19.887) reproduced at tree scale.

Four units close **by construction**, which is stronger than a null: with exactly one live token
there are no pairs or triples to form. `main/trig.c` is live only for `peephole`; the whole
GC/1.2.5n MSL group (`math_8029454c.c`, `acosf.c`, `sincosf.c`) only for `nopeephole`.

`dlls/modgfx/152/152.c` was suspected of hiding a third compiler vocabulary. It does not: ordinary
GC/2.0 at `nopeephole,noschedule`, with a **mixed-direction** live set — `nocse` live *upward*,
`peephole`/`schedule` live *downward*. A uniform toggle direction is inert against that shape; a
sweep must take its directions from the census, per unit.

### Two harness laws, both minted by catching a live defect

**1. `-opt` absolute mode is safe only when the configured `-opt` EQUALS the assumed baseline —
never when it merely CONTAINS it.** `wants_relative()` returns False whenever `nopeephole` and
`noschedule` are both present, but units like `main/pi_videoinit.c`
(`nopeephole,noschedule,nocse,noloopinvariants,nolifetimes,nopropagation`) configure six more
tokens. Replacing wholesale turns several passes back on at once — a demolition, not a probe. This
is the same failure `fn_flag_probe` documents from the opposite direction (units with *no* `-opt`,
where substitution appends and silently disables two passes). Same species, both directions; use
**relative** mode for anything that is not an exact baseline match.

**2. ★ `<=2 equivalence classes from a large probe set is a HARNESS ALARM, not a unit property.**
Seven units produced 1–2 distinct outputs from 84 probes each. That reads exactly like "the flag
axis is dead here" and was in fact the sweep demolishing or failing on every probe. It is the
cheapest possible check and it caught the defect above. **Always print the class count; a sweep
whose outputs do not vary has not run.** Its companion: dedupe by output hash *before* scoring —
measured absorption was 68.4%, so two-thirds of the compute is redundant without it.

## The findings

`Δfn` / `Δunit` are `fuzzy_match_percent`. "Collateral" records effects on the rest of the unit;
the current GC/1.3 revalidation of row 4 is an exception to the earlier negative findings.

| # | unit | function | profile that matches / would match | Δfn | Δunit | collateral / disposition |
|---|---|---|---|---|---|---|
| 1 | `dlls/objects/195_Player/player.c` | `playerUpdate` (2372 B) | **`-opt nocse`** (also `nocse,nopropagation`) — **byte-exact** | 98.432 → 100 | not measured | TU-wide flag change; the unit has 22 sub-100 functions, none re-measured under `nocse`. Conflicts with row 2 — see *The player.c conflict* below. |
| 2 | `dlls/objects/195_Player/player.c` | `fn_802AABE4` (352 B) | **`-opt nopropagation`** (also `nocse,noprop` / `noprop,noauto` / `noprop,inloff`) — **byte-exact** | 97.045 → 100 | not measured | Same TU as row 1 but a *different* profile. Both cannot hold. |
| 3 | `main/audio.c` | `streamsLoadedCallback` (280 B) | **none identified** | 97.643 → 97.057 with the correct source (see note) | 99.93366 → 99.91717 | No `-opt` knob reproduces it. The TU is already `nopeephole,noschedule,nostrength`, so it is outside the peephole/CSE/propagation classes. **The most interesting row: the residual class is not fully covered by the flags anyone has enumerated.** |
| 4 | `main/gameloop_buttonobj.c` | `removeButtonObject` (220 B) | **GC/1.3, `-opt nopeephole,noschedule`, `-inline noauto`** | 98.09091 → 100 | 98.22034 → 100 | Resolved on 2026-09-07: both functions match, with no regressions. The earlier fixed-profile probe's negative result is superseded by the current complete-TU measurement above. |
| 5 | `dlls/.../SaveGame` | `SaveGame_gplaySetObjGroupStatus` | `-opt peephole,noschedule` | 97.981 → 87.746 | 99.743 → 92.652 | Catastrophic: the profile that helps the region destroys the unit. A clear negative. |
| 6 | `main/gametext_tail.c` | `textMeasureFn_80016c9c` (1836 B) | `-opt noloopinvariants` | 98.039 → 98.943 | not recorded | Breaks `gameTextRenderById` **100 → 95.404**. Net loss; the classic shape of this whole table. |
| 7 | `dlls/objects/202/202.c` | `gcRobotPatrol_updateWhileFrozen` (212 B) | **`-opt nocse`** — **byte-exact** | 98.679 → 100 | matched_code 97.570 → **60.358** | **The largest collateral in the table.** Buys exactly 1 function and costs 24, dropping **23 from 100** — `iceBaddie_updateEffectAnchors` 100 → 92.429, `sharpClawHandleHitMessage` 100 → 92.557, `crawler_updateB/C` (1624 B / 1944 B) ≈ 100 → 95.4/95.8. Unit matched functions **135 → 113**. Adjudicated: current `noloopinvariants` stands. |

Rows 1–4 were measured in this lane. Rows 5–6 were measured elsewhere and are relayed here with
their reported numbers so the set is in one place; re-measure before relying on them. A further
`acosf` / `sincosf` / `gameloop_buttonobj` profile sweep exists in the same lane's records and is
**not** reproduced here because this file should not carry numbers nobody in it measured — pull it
from that lane before adjudicating.

### Note on row 7 — why a flag can look right and be a rehome artifact

`-opt nocse` was a genuine, correctly-measured win when `7c3b1b0b2` set it: at that time
gcrobotpatrol was its **own standalone TU** and the flag took its `.text` to 100 with the other
three functions unmoved. The DLL rehome then merged it into `dlls/objects/202/202.c` — today a
138-function object DLL — and `18a7f991e3` set `noloopinvariants` for `crawlerPlayMoveEventFx`
(98.67 → 100, zero per-function regressions). The old flag's evidence did not survive its TU.
**A per-TU flag is only as valid as the TU boundary it was measured on; re-measure every flag a
rehome or merge carries across.**

Also measured: `nocse,noloopinvariants` together is **bit-identical to `nocse` alone**
(60.35806 / 98.70133 / 113) — once CSE is off, loop-invariant motion has nothing left to hoist,
so the combination cannot buy both wins. There is no reconciling profile.

### Note on row 3

`streamsLoadedCallback` is the one row where the *source* question is settled and only the flag
question is open. Line 483 read `gAudioPendingLoadFlags &= ~AUDIO_LOAD_STREAMS;` while **7 of the 8
sibling sites in the same file** write `~(u64)AUDIO_LOAD_X`. The `(u64)` width is load-bearing (cf.
`docs/STYLE.md`): it forces the mask to be materialised — retail `li r0,-5; and r0,r3,r0` — instead
of folding to our `rlwinm r0,r0,0,30,28`. Adding the cast takes the function from 87-vs-86
instructions / 39 positional diffs to **87/87 with REGBLIND 2**, i.e. one moved instruction from
byte-exact.

That one instruction is `li r4,0` — **the loop-invariant stored value** of `s->flag = 0`, not an
induction variable (the counter is strength-reduced away; the body is `stb r4,21(r5)` ×8 with
`addi r5,r5,176`). Retail materialises it in the loop preheader; we hoist it above the two flag
read-modify-writes. Eight source spellings are exactly inert against it — `i = 0; for (; …)`, the
`while` form, an inner block scope for `i`, `i` declared last, `i = i + 1`, a named `int zero`
assigned immediately before the loop, a `u8 zero = 0` in an inner block, and moving the flag writes
below the data reads (that one is *worse*, 99.835). It is an LICM constant-placement decision.

**The cast is the correct source and is deliberately not committed**, because it measures −0.016 on
the unit. It should be landed together with whatever fixes the `li` placement, not before.
| 7 | `dlls/objects/195_Player/player.c` | `playerStateTryCastSpell` (964 B) | **none identified** — not source- and not flag-reachable | — | — | Retail hoists the shared `lis r6,32` high half of two identical `0x200001` call arguments into a saved reg (`lis r30,32`) and derives `addi r6,r30,1` at each site; we rematerialize `lis;addi` twice. In an isolated 2-call probe **4 source spellings** (bare literal, `int f = 0x200001`, `b+1`, `b|1`) and **7 `-opt` profiles x 4 `-O` levels** all emit the un-hoisted form, so it is neither a literal spelling nor an enumerated flag. Most likely a consequence of whole-function register pressure — i.e. band-adjacent, not a source lever. **Third data point for the player.c conflict: this is a *more*-CSE behaviour, while row 1 wants `-opt nocse`.** |

## The `player.c` conflict — an open TU-boundary question

*(Updated: rows 1, 2 and 7 are now three mutually incompatible requirements in one TU —
`nocse`, `nopropagation`, and a hoist that needs* more *CSE than we currently get. Three
conflicting profiles is stronger evidence for a merged-TU boundary than two.)*

`playerUpdate` is byte-exact under `-opt nocse`; `fn_802AABE4` is byte-exact under
`-opt nopropagation`. **Both are in `src/dlls/objects/195_Player/player.c`, and no single profile
satisfies both.**

`CLAUDE.md` names this exact situation: *"conflicting profiles may show that the current unit merges
multiple real TUs, but only DOL evidence may justify correcting that boundary. Never split a
DOL-confirmed TU to isolate a flag profile."*

So this is recorded as a question, with two explicit caveats:

1. **No DOL evidence has been gathered.** Nobody has checked the `.text` function order, the
   `.sdata2` pool partition, `.data`/`.bss` ownership, or source tags around these two functions.
   Until that is done, "merged TU" is a hypothesis with one supporting symptom, not a finding.
2. **A conflicting profile is not sufficient on its own.** Eight other `player.c` functions were
   probed across all nine profiles and matched none of them, so most of the unit's residual is not
   flag-shaped at all. The conflict may equally be two unrelated coincidences.

The useful next step is the DOL audit, not a split.

## How to reproduce

Two tools, already in the tree:

- **`python3 tools/fn_flag_probe.py <unit.c> --symbol <fn> [--symbol …]`** — per *function*, tries
  nine profiles and reports which (if any) make that function **byte-exact**. Fast; the right first
  screen. Its matrix is `as-configured / prop / noprop / nocse / nocse+noprop / noprop+noauto /
  prop+noauto / noprop+inloff / prop+inloff`. **Every one of those profiles is `nopeephole`**, so a
  peephole-*on* hypothesis is not testable with this tool — that is why row 4 is unresolved.
- **`python3 tools/cflag_sweep.py <object_key> <unit_suffix>`** — per *unit*, sweeps TU-level cflag
  profiles and gates on true objdiff fuzzy. Restores and re-runs `configure.py` on exit, including
  on error. This is the tool that produces the collateral column.

**Gating rule.** A per-function byte-exact match is *not* a result on its own. The flag is TU-level,
so the only number that decides anything is the **whole unit's** `fuzzy_match_percent` under the
candidate profile, measured with `tools/unitfuzzy.py` (or `report.json`) — never a diff count, and
never the target function alone. Rows 5 and 6 exist precisely because the per-function number and
the per-unit number pointed in opposite directions.

## Standing caveats

- Do not change `configure.py` from a lane.
- A row that names a profile is *not* a recommendation to adopt it; every such row in this table is
  a net loss at unit scope, which is the finding.
- Re-measure before acting: these numbers were taken against a moving tree.
