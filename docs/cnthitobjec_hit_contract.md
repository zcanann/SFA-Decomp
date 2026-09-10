# CNThitObjec hit and callback contracts

DLL 694 owns EN text `80238AB0..80238FA4`, including the following pickup's
`mcupgrade_SeqFn` at `80238F50`. Its 12-byte profile-pointer table starts at
`8032BEF8`; the 60-byte descriptor at `8032BF04` ends at the next TU's data.
The descriptor advertises ten callbacks and retains one unexplained trailing
zero word, represented separately from the callback type. No boundary moved.

`cnthitobjec_getExtraSize` requests 12 bytes. The recovered state contains
signed health, a pointer to accepted hit priorities, an unsigned count and the
disabled flag. Three profiles accept priorities `{15, 14}`, `{5}`, and no
priorities. The last profile still points at the first table. Its zero count
prevents reads. The count table's fourth byte is opaque, not a fourth profile.
The signed placement byte is cast to `u32`, reduced modulo three and written
back before indexing; this exact conversion and storage behavior is retained.

`ObjHits_GetPriorityHit` returns the selected signed priority separately from
the unsigned hit-volume byte. Its producers truncate that fourth argument to
eight bits when recording a hit. CNThitObjec uses the returned byte as its
health decrement; this does not establish a universal damage meaning for the
engine field. The numeric priorities and mask eight have no proven canonical
source identities and remain literal values.

The placement field at `0x1C` has two evidenced meanings. Visible mode two
copies it directly into rotation X. Other modes use it as the sphere radius
and, when nonzero mode permits an explosion, the explosion scale. Separate
union views preserve the signed-16 storage. Four explosion exclusions compare
placement identities, not model IDs. Visible mode uses a fixed explosion scale
of 80 instead.

Depletion sets the done bit and zeroes health. A later update observes the bit
and latches disabled. The start bit is not cleared, and rendering checks the
disabled latch rather than health. Initialization sets disabled when already
complete but does not explicitly clear it otherwise. No additional resets or
guards were introduced.

The sequence callbacks receive the canonical `ObjSeqState`: `objCallSeqFn`
passes that record and clears its event count afterward. CNThitObjec interprets
each event byte as an explosion scale. The pickup callback checks only whether
any event exists, then reads its own `McUpgradeSetup.dialogueTextId` at `0x1A`.
It no longer casts the neighboring object's placement to a CNThitObjec health
record. That callback remains in its retail-confirmed TU.

CNThitObjec's placement type describes only the reader through `0x21`; no EN
allocation or serialized extent has been established. EN rev1 and JP each have
28 records of 36 bytes: 23 CNThitObjec, four DR_TowerSwi and one CNTColideOb.
The six MCUpgrade records in each secondary version are also 36 bytes.
These widths do not prove the EN extent. Andross's nearest-object lookup uses
CNThitObjec's definition ID `0x6CF`; the canonical header now owns that ID.

Seventeen owner/helper normalized function signatures, the 16-byte priority
and count block, and the 24-byte constant pool agree across all four verified
DOLs. Each version's profile pointers reference its own priority table at
offsets zero, eight and zero. All eleven owner functions, 1,268 code bytes and
112 data bytes remain exact. Full source-object comparisons and objdiff reports
are unchanged across the four targets; the strict EN checksum gates the change.
