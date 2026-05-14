// Non-built exploratory packet for the retail-backed sideload object family.
//
// Source evidence:
// - DLL 0x00EA is "sideload" in retail XML.
// - Object def 0x0495 is "sideload" and uses sideload class 0x001E.
//
// Current EN descriptor:
// - gSideloadObjDescriptor @ 0x80320BB0
//
// Descriptor slots:
// - 4: sideload_update (0x80171BAC)
