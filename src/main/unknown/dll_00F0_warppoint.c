// Non-built exploratory packet for the retail-backed WarpPoint object family.
//
// Source evidence:
// - DLL 0x00F0 is "WarpPoint" in retail XML.
// - Object def 0x04B2 ("WarpPoint") resolves here.
// - Object defs 0x02D2, 0x04B3, 0x0259, and 0x0397 also share this DLL family.
//
// Current EN descriptor:
// - gWarpPointObjDescriptor @ 0x80320DB8
//
// Descriptor slots:
// - 3: WarpPoint_init (0x801776C0)
// - 4: WarpPoint_update (0x80177060)
// - 6: WarpPoint_render (0x80177040)
// - 8: WarpPoint_func08 (0x80177038)
// - 9: WarpPoint_getExtraSize (0x80177030)
//
// Reference-only object parameter hints:
// - 0x18: rotX, signed 8-bit value
// - 0x1A: warpIdx, index into WARPTAB.BIN
// - 0x1C: RomListObjLoadFlags
// - 0x1D: type; 2 means do not warp
// - 0x1E: range
// - 0x20: doWarp GameBit16
