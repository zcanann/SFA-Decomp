// Non-built exploratory packet for the retail-backed DBstealerworm object family.
//
// Source evidence:
// - DLL 0x0242 is "DBstealerworm" in retail XML.
// - Object def 0x0425 is "DBstealerwo" and uses baddie class 0x001C.
// - Object def 0x0539 is an alias of the same retail family.
//
// Current EN descriptor:
// - gDBstealerwormObjDescriptor @ 0x80329774
//
// Descriptor slots:
// - 0: dbstealerworm_initialise (0x80203C58)
// - 1: dbstealerworm_release (0x80203C54)
// - 3: dbstealerworm_init (0x80203AA8)
// - 4: dbstealerworm_update (0x80203670)
// - 5: dbstealerworm_hitDetect (0x80203634)
// - 6: dbstealerworm_render (0x802034C4)
// - 7: dbstealerworm_free (0x8020343C)
// - 8: dbstealerworm_func08 (0x80203434)
// - 9: dbstealerworm_getExtraSize (0x8020342C)
// - 10: DBstealerworm_setScale (0x80203420)
// - 11: dbstealerworm_func0B (0x8020338C)
