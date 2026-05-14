// Non-built exploratory packet for the retail-backed WM_LaserTarget object family.
//
// Source evidence:
// - DLL 0x01FD is "WM_LaserTarget" in retail XML.
// - Object def 0x03AF ("WM_LaserTar") resolves here.
//
// Current EN descriptor:
// - gWM_LaserTargetObjDescriptor @ 0x80328860
//
// Descriptor slots:
// - 0: wmlasertarget_initialise (0x801F20D0)
// - 1: wmlasertarget_release (0x801F20CC)
// - 3: wmlasertarget_init (0x801F206C)
// - 4: wmlasertarget_update (0x801F1F64)
// - 5: wmlasertarget_hitDetect (0x801F1F60)
// - 6: wmlasertarget_render (0x801F1F30)
// - 7: wmlasertarget_free (0x801F1F2C)
// - 8: wmlasertarget_func08 (0x801F1F24)
// - 9: wmlasertarget_getExtraSize (0x801F1F1C)
