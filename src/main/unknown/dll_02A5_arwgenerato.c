// Non-built exploratory packet for the retail-backed ARWGenerato object family.
//
// Source evidence:
// - DLL 0x02A5 is "ARWGenerato" in retail XML.
// - Object def 0x0540 ("ARWGenerato") resolves to this family.
//
// Current EN descriptor:
// - gARWGeneratoObjDescriptor @ 0x8032B8B0
//
// Runtime notes:
// - init seeds extra float +0 from object-def halfword +0x18, and update counts it down
//   before spawning one of two object patterns depending on object-def byte +0x25.
// - the spawn interval is restored from object-def halfword +0x18 after each spawn.
// - variant byte +0x25 selects the helper at 0x802315EC or 0x802317A8, which makes this
//   family a timed ARW object generator rather than a normal visible actor.
//
// Descriptor slots:
// - 0: arwgenerato_initialise (0x80231A8C)
// - 1: arwgenerato_release (0x80231A88)
// - 3: arwgenerato_init (0x80231A58)
// - 4: arwgenerato_update (0x802319A0)
// - 5: arwgenerato_hitDetect (0x8023199C)
// - 6: arwgenerato_render (0x80231978)
// - 7: arwgenerato_free (0x80231974)
// - 8: arwgenerato_func08 (0x8023196C)
// - 9: arwgenerato_getExtraSize (0x80231964)
