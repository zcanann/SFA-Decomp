# Save-select rendering arrays

The EN save-screen renderer consumes the existing `FrontendSaveSlot` records:
the selected record supplies task strings at +0x0c, and the slot list supplies
completion percentages at +0x04 with a 0x24-byte record stride. The records are
allocated using `sizeof(FrontendSaveSlot) * FRONTEND_SAVE_SLOT_COUNT` and are
already indexed directly by the summary loader.

Use those same array members in both render loops. Remove the independent
four-byte task offset and record-byte offset; MWCC derives both strides from
the typed indices. Keep the selected-slot global reload inside the task loop,
as in retail, rather than extending the cached slot pointer across text calls.
The visible task count is limited to three even though the record has five
string slots. Name that display limit separately from the three save slots.

`SaveSelectScreen_run` now obtains the unsigned slot byte with a value cast
instead of dereferencing an alias of the signed-byte global. Both uses retain
their exact generated instructions, including the unsigned API argument.

Under GC/1.3 the renderer retains all 244 instructions and the same control
flow, loads, stores, calls, and loop strides. Register allocation changes in
the two loops: its fuzzy score moves from 99.815575% to 99.52869%. This is a
source-structure recovery, not a new exact-function match. Exact-function and
matched-code-byte counts do not change; every sibling function, existing
allocated data section, and named symbol layout is unchanged. The unit remains
`NonMatching`, so a passing strict checksum uses its retail object.

Validation: object comparison, retail instruction/relocation review, strict
matching checksum, and `ninja all_source` with 30-second timeouts. Formatting
is a separate commit verified to preserve the entire generated object.
