# DLL 704 (TitleScreen): complete EN match

The September 6, 2026 pass takes the unit from 99.836 to 100%: all 23
functions (8,656 bytes) and every data section match, and the unit now links
from source for GSAE01. `titleScreenDrawMenuFrame` went from 99.488 to
byte-identical. The last register was found by capturing the compiler's own
interference graph with `tools/tricky_backend_trace.py`, not by sweeping.

## What the pool order proved

Retail's `.sdata2` places nine of the frame function's constants before the
copyright function's own literals, although only float-free functions precede
it in the text: the int-to-float conversion double, `100`, `-80`, `0`, `-6`,
`268`, `16`, the double `1.0` and the unsigned conversion double. Constants
are emitted where a static helper is first compiled, so those constants come
from helpers defined before `titleScreenShowCopyright`, in that order:

- int-coordinate wrappers around `drawTexture` and `drawScaledTexture`
  (the conversion constant alone comes first);
- `titleScreenSlideX(offset)` and `titleScreenSlideY()` for the bottom bar;
- `titleScreenDrawFrameBottom(mtx)`, whose alpha choice emits `0` before its
  `-6`, `268`, `16`;
- `titleScreenShowTitleText()`, whose `1.0` literal and unsigned conversion
  close the group.

The glow loop's `0.99` and the main texture's `-200`/`250` sit after the pulse
constants, so those blocks are inline. The pool is byte-identical to retail.

## What the compiler trace showed

`tools/tricky_backend_trace.py --unit main/dlls/objects/704/704 --function
titleScreenDrawMenuFrame --graph` captures the GPR graph before simplification
and before rewrite, replays the colouring, and lists the IR at every pass.
Three facts from it settled the function.

Colouring policy. Scratch registers r0 and r3-r12 start enabled. A web takes
the lowest enabled register no neighbour holds; when none is free the next
register of the reserve bank (r31 down to r14) is enabled and taken. Webs are
coloured in reverse simplification order; a node whose initial degree equals
the available count survives the first sweep unless a lower-numbered
neighbour is removed first, and survivors are coloured early.

Node numbering. Inlined-helper locals get the highest numbers, in reverse
call order. The caller's function-scope locals come next in reverse
declaration order, so the first-declared is highest. Its block-scoped locals
are lowest, in reverse program order. A `?:` assignment makes the variable a
high-numbered temporary; an if/else assignment keeps its own number.

Code motion. Invariants are hoisted per basic block, and the loop's second
block was visited before its entry block, so the entry block's `268.0f` load
came last. A `for` loop with the trip count known builds the entry block so
that its constant is hoisted first, and reading the texture table directly
inside the loop lets the counter's init precede the table address as retail
has it.

## The structure that matches

Retail's registers require this order of colouring: the cursor box's y and x,
then the glow loop counter, then the top edge's y, x and alpha, then the
glow x, then the cursor box's first texture, then the loop texture. With the
rules above that fixes the source: the cursor box is inline and uses the
function-scope `yb`, `xb` and `tex`, declared in that order with `i` and the
top edge's `frameY`, `frameX`, `frameAlpha` and the loop's `glowX` between
`i` and `tex`; the top edge is inline with if/else alpha; the bottom edge is a
helper with locals declared `yb`, `a`, `xb` and if/else alpha; the glow loop
is a `for` with a block-scoped `yb` and texture; the slide bar's `texs2` is
block-scoped at its point of use.

Two operand orderings also matter: the glow height is
`(u32)(268.0f * y) + 0x10 + (i + 1) * 6`, and the second slide texture keeps
the converted x in a local before adding the width.
