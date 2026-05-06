// Non-built exploratory packet for the retail-backed SunTemple object family.
//
// Source evidence:
// - DLL 0x0293 is "SunTemple" in retail XML.
// - Known retail object defs using this family include CFSunTemple, WCInvUseObj,
//   and both WCSunTemple variants.
//
// Current EN descriptor:
// - gSunTempleObjDescriptor @ 0x8032B268
//
// Runtime notes:
// - init copies three object-def bytes (+0x18..+0x1A) into object angle fields, installs
//   suntemple_interactCallback at object +0xBC, and seeds extra bytes +0/+1 from the
//   activation bit and player-state selector.
// - update mirrors object-def bit +0x1C into extra byte +0.  While inactive it restores
//   the object transform, hides or shows collision/visibility from the +0x1B/+0x22 flags,
//   and waits for hit/input conditions before raising the activation bit.
// - WCInvUseObj variants use object id 0x0526 plus player bits 0x25A/0x25B/0x202/0x243
//   to choose alternate sequence slots.
// - suntemple_interactCallback handles interaction payload commands, can raise object-def
//   bit +0x1C, writes result 0x100, and optionally triggers the object-def +0x24 action.
//
// Descriptor slots:
// - 0: suntemple_initialise (0x80228B34)
// - 1: suntemple_release (0x80228B30)
// - 3: suntemple_init (0x80228A08)
// - 4: suntemple_update (0x80228658)
// - 5: suntemple_hitDetect (0x80228618)
// - 6: suntemple_render (0x802285E8)
// - 7: suntemple_free (0x802285E4)
// - 8: suntemple_func08 (0x802285DC)
// - 9: suntemple_getExtraSize (0x802285D4)
// - callback: suntemple_interactCallback (0x80228478)
