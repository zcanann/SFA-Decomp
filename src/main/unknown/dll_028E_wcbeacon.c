// Non-built exploratory packet for the retail-backed WCBeacon object family.
//
// Source evidence:
// - DLL 0x028E is "WCBeacon" in retail XML.
// - Object def 0x012A ("WCBeacon") resolves to this family.
//
// Current EN descriptor:
// - gWCBeaconObjDescriptor @ 0x8032B178
//
// Descriptor slots:
// - 3: wcbeacon_init (0x802275DC)
// - 4: wcbeacon_update (0x80227388)
// - 6: wcbeacon_render (0x80227358)
// - 8: wcbeacon_func08 (0x80227328)
// - 9: wcbeacon_getExtraSize (0x80227320)
