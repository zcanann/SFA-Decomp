// Non-built exploratory packet for the retail-backed WM_spiritplace object family.
//
// Source evidence:
// - DLL 0x020C is "WM_spiritplace" in retail XML.
// - Object def 0x03B3 ("WM_spiritpl") resolves here.
//
// Current EN descriptor:
// - gWM_spiritplaceObjDescriptor @ 0x80328C68
//
// Descriptor slots:
// - 0: wmspiritplace_initialise (0x801F6548)
// - 1: wmspiritplace_release (0x801F6544)
// - 3: wmspiritplace_init (0x801F63CC)
// - 4: wmspiritplace_update (0x801F5B38)
// - 5: wmspiritplace_hitDetect (0x801F5B0C)
// - 6: wmspiritplace_render (0x801F5B00)
// - 7: wmspiritplace_free (0x801F5AFC)
// - 8: wmspiritplace_func08 (0x801F5AF4)
// - 9: wmspiritplace_getExtraSize (0x801F5AEC)
//
// Reference-only object parameter hints:
// - 0x18: rotX s8
// - 0x19: unnamed byte
// - 0x1A: rotY s16
// - 0x1C: unnamed s16
// - 0x1E: start GameBit16; starts "placing spirit" anim when set
// - 0x20: enabled GameBit16
