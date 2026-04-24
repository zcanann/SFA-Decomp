// Non-built exploratory packet for the retail-backed CmbSrc object family.
//
// Source evidence:
// - DLL 0x02B1 is "CmbSrc" in retail XML.
// - Object defs 0x059C-0x059F resolve to this family:
//   CmbSrc, CmbSrcTPole, CmbSrcTWall, and ThusterSour.
//
// Current EN descriptor:
// - gCmbSrcObjDescriptor @ 0x8032BDB0
//
// Descriptor slots:
// - 0: cmbsrc_initialise (0x80237570)
// - 1: cmbsrc_release (0x8023756C)
// - 3: cmbsrc_init (0x80236F90)
// - 4: cmbsrc_update (0x80236D84)
// - 5: cmbsrc_hitDetect (0x80236C9C)
// - 6: cmbsrc_render (0x80236BE4)
// - 7: cmbsrc_free (0x80236B80)
// - 8: cmbsrc_func08 (0x80236B78)
// - 9: cmbsrc_getExtraSize (0x80236B70)
