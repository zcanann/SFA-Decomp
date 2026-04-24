// Non-built exploratory packet for the retail-backed ARWSquadron object family.
//
// Source evidence:
// - DLL 0x02A6 is "ARWSquadron" in retail XML.
// - Object defs 0x053B-0x053D and 0x0544-0x0548 resolve to this family:
//   ARWSquadron, ARWBigAster, ARWSmallAst, ARWMobileGu, ARWGroundGu,
//   ARWShipFly, ARWShipTwin, and ARWShipAnge.
//
// Current EN descriptor:
// - gARWSquadronObjDescriptor @ 0x8032B8E8
//
// Descriptor slots:
// - 3: arwsquadron_init (0x80232D74)
// - 4: arwsquadron_update (0x80232830)
// - 5: arwsquadron_hitDetect (0x8023282C)
// - 6: arwsquadron_render (0x80232808)
// - 7: arwsquadron_free (0x80232804)
// - 8: arwsquadron_func08 (0x802327FC)
// - 9: arwsquadron_getExtraSize (0x802327F4)
