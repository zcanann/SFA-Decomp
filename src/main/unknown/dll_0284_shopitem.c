// Non-built exploratory packet for the retail-backed ShopItem object family.
//
// Source evidence:
// - DLL 0x0284 is "ShopItem" in retail XML.
// - Known retail object defs using this family include SPFruitSmal, SPEggSmall,
//   SPFruitLarg, SPEggLarge, SPBombSpore, SPMoonSeed, SPLantern, SPBlueArtef,
//   SPBlueMushr, SPSwapGift, SPPda, SPBinocular, SPFireFly, SPFuelCell,
//   SPSidekickB, SPDusterHol, SPStaffHitB, SPMapTTH, SPMapMMP, SPMapLF,
//   SPMapCRF, SPMapDIM, SPMapWC, SPMapDR, SPMapKP, SPMapOFP, SPMapSW,
//   SPMapVFP, SPMapCC, and SPReplayDis.
//
// Current EN descriptor:
// - gShopItemObjDescriptor @ 0x803283E0
//
// Descriptor slots:
// - 0: shopitem_initialise (0x801E8EA0)
// - 1: shopitem_release (0x801E8E9C)
// - 3: shopitem_init (0x801E8D7C)
// - 4: shopitem_update (0x801E8968)
// - 5: shopitem_hitDetect (0x801E8964)
// - 6: shopitem_render (0x801E8910)
// - 7: shopitem_free (0x801E88B8)
// - 8: shopitem_func08 (0x801E88B0)
// - 9: shopitem_getExtraSize (0x801E88A8)
