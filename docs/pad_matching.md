# Controller input matching (2026-09-07)

`src/main/pad.c` is now `MatchingFor("GSAE01")`: all 26 functions, 3,068
code bytes, and 260 data bytes match. The complete source-linked DOL passes
the strict retail checksum.

| Measure | Before | After |
| --- | ---: | ---: |
| Unit fuzzy match | 99.89570% | 100% |
| Exact functions | 25 / 26 | 26 / 26 |
| `padUpdate` | 99.76811% | 100% |
| `padUpdate` instructions | 345 | 345 |
| `initControllers` instructions | 94 | 94 |

## Native storage and indexed loops

The synthetic `PadStateBlock` overlay, its one-element local pointer arrays,
and offsets into neighboring globals are removed. The BSS span has independent
button-state arrays and an eight-record status buffer:

| BSS offset | Definition | Bytes |
| --- | --- | ---: |
| 0x00 | previous buttons, four ports | 16 |
| 0x10 | held buttons, four ports | 16 |
| 0x20 | released buttons, four ports | 16 |
| 0x30 | newly pressed buttons, four ports | 16 |
| 0x40 | eight `PADStatus` records | 96 |

The status-buffer index alternates between zero and one. Each SDK read uses
four consecutive records, so the flat buffer expresses every existing access
without indexing beyond the first row of a two-dimensional array. Its
0x60-byte size is asserted. Array dimensions and loop limits use the SDK's
`PAD_MAX_CONTROLLERS`; the public button-array declarations now include their
proven four-element bounds. Trigger synthesis uses the existing SDK trigger
bits instead of duplicate local definitions.

Both `initControllers` and `padUpdate` use indexed accesses to the native
arrays. MWCC generates the pointer cursors and increments itself. The update
has six locals, down from 23; initialization has one, down from 18.

Native storage alone preserved the previous near match. The last difference
was twelve r14/r16 operands shared by the previous input buffer, the current
read buffer, and the generated button-mask cursor. Fully indexed accesses,
including both status buffers, recover the retail allocation. Partially
retaining explicit cursors leaves different live ranges and does not match.
All other functions preserve their raw instruction bytes.

Disconnect clearing, failed-read fallback, button transitions, trigger
thresholds, stick repeat, reset handling, and buffer selection retain their
retail behavior and signedness. In particular, the update still reloads the
stored signed stick bytes before evaluating repeat timing.

## Compiler and source order

The compiler remains the common game GC/1.3, with the existing
`nopeephole,noschedule,nocse` optimization settings and automatic inlining.
The TU adds deferred emission. Ordinary function definitions are ordered for
reverse emission, and the native globals are defined before the functions.
MWCC then creates the shared BSS base used by the retail initialization and
update. No TU boundary, per-function setting, or forced section is introduced.

The Dinosaur Planet reference's `src/joypad.c` provides independent source
lineage for separate controller arrays, indexed per-controller updates, and
initialization before the input processing code. EN's reverse function order
and shared-base instructions provide the target evidence. As a further check,
`padUpdate` now calls the existing `stopRumble` function: deferred automatic
inlining reproduces the same instructions even though that helper's definition
follows the update in source.

## Validation

- `ninja all_source` and the matching build succeed, each with a 30-second
  timeout. The final DOL is byte-identical to the preceding retail build and
  passes `config/GSAE01/build.sha1` with the controller TU linked from source.
- Objdiff reports every function and all 260 allocated data bytes exact.
- Every named non-text symbol retains its section, offset, size, and linkage.
  All allocated non-text section bytes, sizes, and alignments are preserved.
- The canonical header is included first; no shared consumers require edits.
- Both files pass `clang-format --dry-run --Werror`. Running the formatter
  leaves them unchanged, so no separate formatting commit is needed. The
  complete compiled object is unchanged by that check.
