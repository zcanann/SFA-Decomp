// Non-built exploratory packet for the retail-backed WCLevelCont object family.
//
// Source evidence:
// - DLL 0x028D is "WCLevelCont" in retail XML.
// - Object def 0x0122 ("WCLevelCont") resolves to this family.
//
// Current EN descriptor:
// - gWCLevelContObjDescriptor @ 0x8032B108
//
// Runtime notes:
// - init installs a callback at object +0xBC, clears puzzle bits 0x810/0x811,
//   mirrors story bits 0x7FA/0x7F9/0x813/0x812/0x2A5/0x205/0xBCF/0xCAC into
//   extra halfword +0x1A, and seeds controller mode byte +0x0C.
// - update dispatches to the WCPushBlock helper pair through player-state slot 0x40,
//   then calls wclevelcont_syncProgressBits on the controller extra block.
// - wclevelcont_syncProgressBits maintains the active event/object ids at extra
//   +0x16/+0x18 and pushes the level-progress bit fanout for ids 0xBA6/0xCCE/0xCD0/
//   0xCBB/0xF31.
//
// Descriptor slots:
// - 0: wclevelcont_initialise (0x802272C4)
// - 1: wclevelcont_release (0x802272C0)
// - 3: wclevelcont_init (0x8022705C)
// - 4: wclevelcont_update (0x80226EF4)
// - 5: wclevelcont_hitDetect (0x80226D48)
// - 6: wclevelcont_render (0x80226D18)
// - 7: wclevelcont_free (0x80226C6C)
// - 8: wclevelcont_func08 (0x80226C64)
// - 9: wclevelcont_getExtraSize (0x80226C5C)
// - internal: wclevelcont_syncProgressBits (0x80226D4C)
// - 10: wclevelcont_setScale (0x80226B84)
// - 11: wclevelcont_func0B (0x80226A98)
// - 12: wclevelcont_modelMtxFn (0x80226A50)
// - 13: wclevelcont_render2 (0x80226A08)
// - 14: wclevelcont_func0E (0x802269A8)
// - 15: wclevelcont_func0F (0x80226948)
// - 16: wclevelcont_func10 (0x802264C4)
// - 17: wclevelcont_func11 (0x802263EC)
// - 18: wclevelcont_func12 (0x80226300)
// - 19: wclevelcont_func13 (0x802262B8)
// - 20: wclevelcont_func14 (0x80226270)
// - 21: wclevelcont_func15 (0x80226210)
// - 22: wclevelcont_func16 (0x802261B0)
