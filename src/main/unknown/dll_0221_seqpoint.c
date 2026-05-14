// Non-built exploratory packet for the retail-backed SeqPoint object family.
//
// Source evidence:
// - DLL 0x0221 is "SeqPoint" in retail XML.
// - Object defs 0x032C, 0x03F1, 0x03FC, 0x0404, 0x0412, and 0x041C share this DLL family.
//
// Current EN descriptor:
// - gSeqPointObjDescriptor @ 0x803290F8
//
// Descriptor slots:
// - 0: seqpoint_initialise (0x801FCCE4)
// - 1: seqpoint_release (0x801FCCE0)
// - 3: seqpoint_init (0x801FCC5C)
// - 4: seqpoint_update (0x801FC9AC)
// - 5: seqpoint_hitDetect (0x801FC9A8)
// - 6: seqpoint_render (0x801FC978)
// - 7: seqpoint_free (0x801FC974)
// - 8: seqpoint_func08 (0x801FC96C)
// - 9: seqpoint_getExtraSize (0x801FC964)
//
// Reference-only object parameter hints:
// - 0x18: rotation s8
// - 0x19: mode byte
// - 0x1A: maxDist s16
// - 0x1C: seqIdx s16
// - 0x1E: unnamed GameBit16
// - 0x20: bitDone GameBit16
