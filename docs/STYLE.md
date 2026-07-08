# Source layout & style contract

This is the opinionated baseline for every `.c` unit under `src/main/`. New code and any
touched file must conform. `src/main/dll/WM/dll_020C_wmspiritplace.c` is the reference
example. Formatting (whitespace/braces) is governed by the repo `.clang-format`
(4-space, Allman, pointer-left, 120 cols, ≤1 consecutive blank line) and is applied
tree-wide; run `clang-format -i` on any file you touch.

## Canonical unit layout (top to bottom)

1. **File doc-comment** — one block comment: what the unit is (DLL id, actor, subsystem)
   and how it behaves at runtime. Current-state only; never edit history.
2. **`#include`s** — one block, no blank lines inside. Order is authored, not sorted;
   never add an include that duplicates one already reachable and never keep two
   includes of the same header.
3. **Types** — `typedef struct/enum/union` definitions, offset-annotated fields
   (`/* 0xNN: meaning */`).
4. **`STATIC_ASSERT`s** — immediately after the types they check.
5. **Constants** — `enum`s and `#define`s, topically grouped, one blank line between
   groups. Unit-local constants are named `<UNIT>_<NAME>`.
6. **Extern declarations** — cross-unit data first, then cross-unit functions. Only
   externs actually used by this unit; only at file scope (block-scope externs are
   banned). Prefer including the owning header when one declares the symbol with the
   byte-matching type spelling.
7. **Own-function prototypes** — forward decls for this unit's functions.
8. **Data definitions** — descriptors, tables, file-scope variables.
9. **Function definitions.**

Exactly one blank line between every pair of top-level items.

**Externs are a last resort.** A symbol owned by a unit with a per-unit header comes
from that header — including function addresses feeding pointer tables. A file-local
extern is only acceptable when no header declares the symbol with the byte-matching
type spelling. Marker comments like `/*__DATA_EXTERNS__*/` are generator cruft:
delete them.

**Comments travel with their subject.** A comment documents the declaration or
definition directly below (or beside) it; whoever moves the subject moves the
comment — into a header if that is where the subject went. A comment left pointing
at code that is no longer there is a defect.

## Per-unit headers

A unit's struct typedefs, their `STATIC_ASSERT`s, and its exported prototypes live in a
per-unit header mirroring the source path (`src/main/dll/WM/dll_020C_wmspiritplace.c`
→ `include/main/dll/WM/dll_020C_wmspiritplace.h`), guarded
`#ifndef MAIN_DLL_WM_DLL_020C_WMSPIRITPLACE_H_`-style. The `.c` includes it first.
Constants and data definitions stay in the `.c`.

## Byte-match constraints (non-negotiable, override everything above)

The retail `.o` bytes are the ground truth; layout moves must be codegen-neutral:

- **Never reorder function definitions** (`.text` order) or **data definitions**
  (`.data`/`.bss` emission order).
- **Never move or reorder `#pragma`s** (`dont_inline`, `peephole`, `scheduling`).
- **Never change a declaration's type spelling** while moving it. Signedness of extern
  decls is load-bearing: `int` vs `u32` flips `cmpwi`/`cmplwi` at compare sites. If a
  local extern's spelling differs from every header's, it stays local, as spelled.
- **SJIS-bearing files** (non-ASCII bytes) are edited byte-wise (python `rb`/`wb`),
  never through text tools or formatters.
- Gate every sweep: `ninja all_source` must exit 0 and every `.o` must be md5-identical
  (case-normalized paths — the build dir has case-twin objects); no unit's
  `fuzzy_match_percent` may drop.
