// Non-built exploratory packet for the retail-backed VFP_flamepoint object family.
//
// Source evidence:
// - DLL 0x0225 is "VFP_flamepoint" in retail XML.
// - Object def 0x0319 ("VFP_flamepo") resolves here.
// - Retail hint: things Tricky needs to use flame on.
//
// Current EN descriptor:
// - gVFP_flamepointObjDescriptor @ 0x803291D8
//
// Descriptor slots:
// - 3: vfpflamepoint_init (0x801FD66C)
// - 4: vfpflamepoint_update (0x801FD4EC)
// - 9: vfpflamepoint_getExtraSize (0x801FD4E4)
//
// Reference-only object parameter hints:
// - 0x1A: unnamed undefined2
// - 0x1C: unnamed undefined2
// - 0x1E: activated GameBit16; presumably set when using flame
// - 0x20: maybeEnabled GameBit16
