// Non-built exploratory packet for the retail-backed Pushable object family.
//
// Source evidence:
// - DLL 0x00EF is "Pushable" in retail XML.
// - This family backs pushable blocks, boulders, and related movable props.
//
// Current EN descriptor:
// - gPushableObjDescriptor @ 0x80320D48
//
// Descriptor slots:
// - 3: pushable_init (0x801769B4)
// - 4: pushable_update (0x801766E8)
// - 5: pushable_hitDetect (0x801760E4)
// - 6: pushable_render (0x80175FB8)
// - 7: pushable_free (0x80175EC8)
// - 8: pushable_func08 (0x80175EC0)
// - 9: pushable_getExtraSize (0x80175EB8)
// - A: pushable_setScale (0x801755CC)
// - B: pushable_func0B (0x8017554C)
// - C: pushable_modelMtxFn (0x80175530)
// - D: pushable_render2 (0x80175520)
