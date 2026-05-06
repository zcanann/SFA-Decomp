// Non-built exploratory packet for the retail-backed FirePipe object family.
//
// Source evidence:
// - DLL 0x0273 is "FirePipe" in retail XML.
// - Known retail object defs using this family include:
//   0x0086 BossDrakorF
//   0x0464 FirePipe
//   0x0466 FireHole
//   0x0467 FlameMuzzle
//   0x0468 IceHole
//   0x0469 SteamHoleNo
//   0x046A SteamHoleFi
//   0x046B SteamHoleDe
//
// Current EN descriptor:
// - gFirePipeObjDescriptor @ 0x8032AC90
//
// Internal helpers immediately before the descriptor slots:
// - firepipe_spawnEffectObject (0x8021F8CC): pooled spawn/reuse for up to eight effect objects.
// - firepipe_releaseEffectObject (0x8021FA38): releases pooled effect objects or frees unpooled ones.
// - firepipe_clearLinkedUpdateFlag (0x8021FAB4): clears extra flag bit 2 on linked child effects.
// - firepipe_setLinkedUpdateFlag (0x8021FAD0): sets extra flag bit 2 on linked child effects.
// - firepipe_updateState (0x8021FAEC): shared runtime update body used by update and callback.
//
// Descriptor slots:
// - 3: firepipe_init (0x802202B8)
// - 4: firepipe_update (0x80220288)
// - 6: firepipe_render (0x802201E0)
// - 7: firepipe_free (0x80220164)
// - 8: firepipe_func08 (0x8022015C)
// - 9: firepipe_getExtraSize (0x80220130)
