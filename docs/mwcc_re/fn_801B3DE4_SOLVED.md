# fn_801B3DE4 (dll_01CA_dimexplosion) — SOLVED, 100% (2026-06-21)

Supersedes fn_801B3DE4_partial.md (which concluded "banked at 98.04%, impossible").
It was NOT impossible. Two clean-C levers, found by reading the asm + measuring
*structural distance* (not just fuzzy %), close it byte-for-byte.

## The two divergences and their fixes

### A — `mr r29,r31`: the 0x14/lifetime base needs its own saved reg
The target keeps `state+off` in TWO overlapping saved regs (r31=e for all fields,
r29=e14 for 0x14 only), joined by a surviving `mr` copy. The front-end value-numbers
two identical `state+off` into one web, so a plain second pointer folds. Defeat the
merge with a no-op bitwise op whose value is still `state+off`:

    int e14;                          /* DECLARE FIRST -> lands in r29 */
    ...
    int life = (int)(K * sqrtf(spd)); /* compute lifetime to a temp first... */
    e14 = state + off;
    e14 |= e;                         /* ...|= e (==state+off): mr r29,r31 + separate web, no branch */
    *(int*)((char*)e14 + 0x14) = life;/* placed AFTER sqrtf -> mr at the right position */

`e14 |= e` emits `or r29,r31,r31` (== `mr r29,r31`) and keeps e14 a distinct web
because the `|` node blocks the value-number merge. Declaring e14 first pins it to r29;
doing this after the sqrtf temp aligns the mr to the target's position.

### B — random section: per-call re-derive of the slot base, `add state,off` order
Target recomputes the 0x28/0x2c slot address fresh into volatile r3 after each
`randomGetRange` call (calls clobber r3), and uses r27 for the multi-use 0x2a base.
Mine hoisted one base into saved r27. Fix = recipe #112 K-grouping, grouping the field
offset onto the *base pointer* (not the index):

    *(s16*)((char*)((char*)state + 0x28) + idx * 0x30) = randomGetRange(...);

`((char*)state + K) + idx*0x30` makes each store's base value-number distinct (different
K) -> no CSE -> re-derives per call; and because K is grouped onto `state`, the displacement
folds into the store and the add is emitted `add r3,r28,r30` (state,off order) — matching.
NOTE: grouping K onto the *index* (`state + (idx*0x30 + K)`) also re-derives but flips the
add to off,state order (`add r3,r30,r28`) — that was the last 3-byte gap (99.83 -> 100).

## Method note
The breakthrough came from a structural-distance metric (`tools`-style /tmp/rd.py: count real
instruction/reg diffs vs target, ignoring score-neutral @NNN reloc names and subi/addi display).
It exposed that a 96% variant could be *structurally closer* than the 98% baseline — fuzzy %
alone hid the path. Always read the emitted asm per variant; don't fail-fast on the headline %.
