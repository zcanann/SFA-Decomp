// Non-built exploratory packet for the retail-backed WM_seqpoint object family.
//
// Source evidence:
// - DLL 0x020D is "WM_seqpoint" in retail XML.
// - Object def 0x03B5 ("WM_seqpoint") resolves here.
//
// Current EN descriptor:
// - gWM_seqpointObjDescriptor @ 0x80328CF0
//
// Descriptor slots:
// - 0: wmseqpoint_initialise (0x801F6E88)
// - 1: wmseqpoint_release (0x801F6E84)
// - 3: wmseqpoint_init (0x801F6E00)
// - 4: wmseqpoint_update (0x801F6A88)
// - 5: wmseqpoint_hitDetect (0x801F6A84)
// - 6: wmseqpoint_render (0x801F6A54)
// - 7: wmseqpoint_free (0x801F6A50)
// - 8: wmseqpoint_func08 (0x801F6A48)
// - 9: wmseqpoint_getExtraSize (0x801F6A40)
//
// Reference-only object parameter hints:
// - 0x18: rotation byte
// - 0x19: action byte
// - 0x1A: trigDist s16
// - 0x1C: seqIdx s16
// - 0x1E: seqStarted GameBit16
// - 0x20: unnamed GameBit16
