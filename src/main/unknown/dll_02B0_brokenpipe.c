// Non-built exploratory packet for the retail-backed BrokenPipe object family.
//
// Source evidence:
// - DLL 0x02B0 is "BrokenPipe" in retail XML.
// - Object defs in this family include BrokenPipe, MetalRafter, BoulderOne,
//   RedBoulder, Cactus, and SnowBoulder.
//
// Current EN descriptor:
// - gBrokenPipeObjDescriptor @ 0x8032BCC8
//
// Descriptor slots:
// - 3: brokenpipe_init (0x80236194)
// - 4: brokenpipe_update (0x8023615C)
// - 9: brokenpipe_getExtraSize (0x80236154)

// Runtime shape:
// - init seeds decorative rotation from object-def bytes +0x18/+0x19/+0x1A,
//   scales the model from object-def byte +0x1B, adjusts hit radius from the
//   model data, and marks the object hidden/solid through obj flag 0x4000.
// - update polls a standard hit interaction with the configured break colors
//   and hit animation id 0x6F.
