// Non-built exploratory packet for the retail-backed SB_ShipHead object family.
//
// Source evidence:
// - DLL 0x01EA is "SB_ShipHead" in retail XML.
// - Object def 0x02FD is "SB_ShipHead" and uses various0030 class 0x0030.
// - Object def 0x00F7 is an alias of the same retail family.
//
// Current EN descriptor:
// - gSB_ShipHeadObjDescriptor @ 0x80327CC0
//
// Descriptor slots:
// - 3: SB_ShipHead_init (0x801E324C)
// - 4: SB_ShipHead_update (0x801E2CE4)
// - 6: SB_ShipHead_render (0x801E2B5C)
// - 7: SB_ShipHead_free (0x801E2B38)
// - 8: SB_ShipHead_func08 (0x801E2B30)
// - 9: SB_ShipHead_getExtraSize (0x801E2B28)
