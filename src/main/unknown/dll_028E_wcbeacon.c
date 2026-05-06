// Non-built exploratory packet for the retail-backed WCBeacon object family.
//
// Source evidence:
// - DLL 0x028E is "WCBeacon" in retail XML.
// - Object def 0x012A ("WCBeacon") resolves to this family and has alias 0x050F.
// - The generic object setup special-cases object id 0x050F and installs
//   wcbeacon_aButtonCallback as its a-button interaction handler.
//
// Current EN descriptor:
// - gWCBeaconObjDescriptor @ 0x8032B178
//
// Runtime notes:
// - init copies object-def byte +0x19 into object byte +0xAD, clamps it against model
//   data, and seeds extra byte +4 from the completion/open bits at object-def +0x20/+0x1E.
// - update alternates between inactive, active, post-use delay, and opened states.  The
//   opened path plays sequence 0x69, toggles visibility, and can fire effect/sound id 0x73A.
// - wcbeacon_aButtonCallback sets extra byte +5 and raises the object-def +0x1E bit when
//   the interaction is accepted, which drives the post-use transition in update.
//
// Descriptor slots:
// - 3: wcbeacon_init (0x802275DC)
// - 4: wcbeacon_update (0x80227388)
// - 6: wcbeacon_render (0x80227358)
// - 8: wcbeacon_func08 (0x80227328)
// - 9: wcbeacon_getExtraSize (0x80227320)
// - interaction: wcbeacon_aButtonCallback (0x802272C8)
