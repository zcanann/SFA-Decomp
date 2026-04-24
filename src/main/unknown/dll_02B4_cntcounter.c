// Non-built exploratory packet for the retail-backed CNTcounter object family.
//
// Source evidence:
// - DLL 0x02B4 is "CNTcounter" in retail XML.
// - Object def 0x030E ("CNTcounter") resolves to this family.
//
// Current EN descriptor:
// - gCNTcounterObjDescriptor @ 0x8032BE88
//
// Descriptor slots:
// - 0: cntcounter_initialise (0x80238528)
// - 1: cntcounter_release (0x80238524)
// - 3: cntcounter_init (0x80238510)
// - 4: cntcounter_update (0x8023842C)
// - 5: cntcounter_hitDetect (0x80238428)
// - 6: cntcounter_render (0x80238424)
// - 7: cntcounter_free (0x802383F0)
// - 8: cntcounter_func08 (0x802383E8)
// - 9: cntcounter_getExtraSize (0x802383E0)
