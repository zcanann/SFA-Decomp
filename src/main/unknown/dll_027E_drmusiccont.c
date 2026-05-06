// Non-built exploratory packet for the retail-backed DRMusicCont object family.
//
// Source evidence:
// - DLL 0x027E is "DRMusicCont" in retail XML.
// - Object def 0x047A ("DRMusicCont") resolves to this family.
//
// Current EN descriptor:
// - gDrMusicContObjDescriptor @ 0x8032AD98
//
// Runtime notes:
// - init snapshots puzzle/music game bits 0xE30-0xE33, 0xE38-0xE3E/0xE39,
//   and 0x9E0-0x9E2/0x9E7 into extra bytes +8/+9.
// - update watches the same bit groups and plays success/failure cues:
//   all 0xE30-0xE33 set latches bit 0xE9C and plays SFX 0x7E; changed partial
//   states play SFX 0x109.
// - if the 0x9E0/0x9E1/0x9E2/0x9E7 group regresses, extra +4 becomes a countdown
//   that eventually plays SFX 0x4BD.
// - update toggles a world effect through DAT_803DCAAC when 0x9F0 is set and 0x632 is clear.
//
// Descriptor slots:
// - 0: drmusiccont_initialise (0x80221174)
// - 1: drmusiccont_release (0x80221170)
// - 3: drmusiccont_init (0x80220FF8)
// - 4: drmusiccont_update (0x80220B34)
// - 5: drmusiccont_hitDetect (0x80220B30)
// - 6: drmusiccont_render (0x80220B00)
// - 7: drmusiccont_free (0x80220AE0)
// - 8: drmusiccont_func08 (0x80220AD8)
// - 9: drmusiccont_getExtraSize (0x80220AD0)
