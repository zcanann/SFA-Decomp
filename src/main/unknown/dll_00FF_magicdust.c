// Non-built exploratory packet for the retail-backed MagicDust object family.
//
// Source evidence:
// - DLL 0x00FF is "MagicDust" in retail XML.
// - Retail description: magic gem (same params as MoonSeedCol?).
// - Current EN family packet data ties MagicDustMi / La / Sm / Hu here.
//
// Current EN descriptor:
// - gMagicDustObjDescriptor @ 0x80320CC4
//
// Descriptor slots:
// - 3: magicdust_init (0x80173AEC)
// - 4: magicdust_update (0x801732A4)
// - 6: magicdust_render (0x80173280)
// - 7: magicdust_free (0x8017322C)
// - 9: magicdust_getExtraSize (0x80173224)
