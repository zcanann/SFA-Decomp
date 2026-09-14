# Game-text line wrapping

`gameTextWrapLines` is at EN/JP `0x80016C9C` and EN rev1/PAL rev1
`0x80016CD4`, with a 1,836-byte retail body. Its third parameter is a glyph
scale, not a height constraint. `gameTextRenderStrs` supplies a text box's
width and scale, then uses the returned maximum line height to advance its
vertical cursor.

**EN status (2026-09-14): 100% matching**, including every relocated instruction
against the verified retail DOL. The code TU has 52 of 54 exact functions and
remains `NonMatching` because two other functions are unfinished.

The source now distinguishes the scanning byte offset, copying byte offset,
last candidate wrap position, line-start table, and its two traversal pointers.
Font selection uses the existing font IDs and a read-only `FontMetrics` view.
The table strides and pointer-table allocation use their actual element sizes.
The neutral `byteCount` local retains two measured lifetimes: UTF-8 sequence
length during scanning, then total allocation size. Separating that local or
replacing the byte-offset table stores with direct indexing changes codegen.

## Scanning and storage

Each recognized glyph advances the line by
`scale * (width + offsetX + advanceX)`. The glyph width is unsigned, while both
horizontal offsets are signed bytes. Unknown glyphs remain in the copied text
but do not advance the line. A line breaks when its accumulated width is
**greater than or equal to** the width limit.

An ASCII space records a candidate break immediately after itself. On overflow,
the scan restarts at that candidate; without a space, it restarts before the
current glyph. The copying pass trims trailing whitespace through the existing
UTF-8 lookbehind helper. That helper recognizes U+0020, U+3000, and U+303F,
although only U+0020 records a candidate during the scanning pass.

Control arguments are big-endian byte pairs held in the existing working-int
array. SCALE changes the scale from its 8.8 fixed-point argument; FONT changes
the selected metrics. Both commands can increase the reported maximum line
height, except while the face font is selected. The initial line height is
recorded before scanning, so a later smaller scale never lowers it.

The allocation contains a native pointer table followed by copied text and
room for one terminator per counted line. Its size on the target is
`input byte count + line count + line count * sizeof(char*)`. A non-null
maximum-height output selects `mmAllocateFromFBMemoryStore`; without it,
the function uses `mmAlloc`. This allocation choice is part of the API,
not merely an optional measurement result.

## Retail edge behavior

- A null input returns null with line count zero; an empty string returns null
  with line count one. Both initialize the optional height output first.
- Repeated wrap positions and a thirtieth intermediate break return null
  before publishing the line count. Thirty final lines are valid; thirty-one
  are rejected in the covered ordinary-text cases.
- Allocation failure returns null after publishing the line count.
- If either global cursor coordinate is nonzero, the width limit becomes
  the global X coordinate. A nonzero Y with zero X therefore selects zero width.
- A trailing-space break at the terminating byte can count one extra line
  whose pointer stays null. With five-pixel fixture glyph advances,
  `"A "` repeated 32 times at width 40 returns count nine, eight populated
  pointers, and a null ninth pointer. The last populated line retains its
  trailing space: there is no copied byte at the terminal boundary to trigger
  the trimming helper. The source preserves this behavior.

## Executable evidence

Run `python3 tools/gametext_wrap_probe.py` with the optional `unicorn` and
`pyelftools` dependencies installed, after building the EN gametext object.
The probe verifies the configured retail SHA-1 before loading the DOL. It runs
the full retail and compiled wrapper, including their glyph scans, UTF-8
reader, control parsing, copying, and register-save helpers. Only the two
allocation functions are mocked; those callbacks poison volatile registers.

The 151 comparisons include ASCII and multibyte glyphs, missing glyphs,
repeated and Unicode spaces, equal-width overflow, 29/30/31-line boundaries,
null/empty input, scale arguments through 65535, font changes, both allocation
paths and failures, and cursor overrides. They compare the full allocated
block, pointer results, line count, height, and allocation calls. They also
check immediate heap guards and preserved GPR/FPR/paired-single state,
stack/SDA registers, and nonvolatile condition-register fields. Independent
expected results cover ordinary line contents, allocation sizes, height
changes, limits, and the trailing null pointer; agreement alone would not
catch a shared fixture mistake.

The initial source-and-contract recovery pass retained a 96.45098% match.
Its cross-version verification checked the normalized
retail function shape and raw source object identity; EN execution does not
claim that every regional text resource or malformed input has been exercised.

All four `all_source` builds passed in 19.90, 21.89, 20.13, and 21.29 seconds.
Every existing compiled source object retained its hash (1,004 in the EN
build directory and 988 in each secondary directory), and each complete
objdiff report is unchanged. The gametext objects are identical across all
four versions. The 16 existing gametext tests also pass. Formatting the TU and
API header is a no-op; the final EN `all_source` and strict retail checksum
checks pass in 19.65 and 21.17 seconds, within their 30-second limits.

## Copy-loop allocation pass (2026-09-14)

With the common GC/1.3 profile, `gameTextWrapLines` improves from 98.932465%
to 99.3573%, retaining its 1,836-byte body. The line-break operation now lives
inside the copy loop, so its trimming and insertion both update the same write
cursor. The copied-byte offset advances before the input pointer, as in retail.
A small declaration-order adjustment preserves the improved allocation. The
obsolete private `gameTextBreakLine` helper is removed.

There are still 57 differing instruction words, all register operands. The
input and output parameters, font state, boundary-table pointer, allocation
size, and saved break character still receive different registers. The other
51 exact functions, named storage layouts, and allocated non-text bytes are
unchanged; this is not a claim of an exact function or complete source TU.

The GC/1.3 LLDB trace reproduces the ordinary object and records allocation
without modifying compiler state:

```sh
python3 tools/tricky_backend_trace.py --unit main/main/gametext \
    --function gameTextWrapLines --graph --output build/wrap_match/final_trace
```

The emulation probe now links `gametext_data.o` alongside the selected code
object. Its previous generic external-data stubs replaced the recovered UTF-8
masks and control-length table with zeros after the initialized-data split;
both the pre-change and current source object failed that stale fixture.
With the actual data object, both pass all 151 retail comparisons, including
multibyte characters, control arguments, complete allocation contents, and ABI
preservation. The 20 existing gametext tests also pass.

## Exact register allocation (2026-09-14)

`gameTextWrapLines` now matches all 459 instructions (1,836 bytes), up from
99.3573%. The existing general counter holds the control-argument count while
a scoped index fills the argument array. The clearing and copying passes use
separate cursors, and the line index belongs to the copying scope. Keeping the
recovered declaration order reproduces GC/1.3's saved-register allocation.
No compiler settings, pragmas, assembly, or TU boundaries changed.

The ordinary and LLDB-instrumented compiler builds agree. Objdiff reports
100% for the wrapper and 99.907104% for the code TU. All other function bytes,
named symbol layouts, non-text section contents, and resolved relocation
destinations remain unchanged; compiler-generated anonymous labels renumber.
The new relocation regression test resolves calls and data references to their
actual retail addresses and compares the complete function against the
hash-verified EN DOL. All 21 gametext tests and 151 retail/compiled execution
cases pass. Only the EN retail input is available in this checkout, so this
pass makes no new regional matching claim.

The final EN `ninja all_source` and strict checksum builds pass in 16.33 and
17.14 seconds, respectively, within their 30-second limits. The TU and API
header pass the required clang-format check.
