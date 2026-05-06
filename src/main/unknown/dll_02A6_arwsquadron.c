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
// Runtime notes:
// - init classifies object ids into squadron/asteroid/mobile-gun/ship variants, seeds
//   route bounds from object-def bytes, and optionally attaches to a leader object through
//   extra +0x13C.
// - update waits for the arwing to enter the configured altitude window, reveals the model,
//   and then either follows the active path, follows its leader, or runs attack/damage
//   behavior depending on extra state byte +0x159 and mode byte +0x15C.
// - arwsquadron_applyCommandParams consumes object-def command bytes and adjusts target
//   speed, attack flags, and timers.
// - arwsquadron_followLeader mirrors the leader transform with sinusoidal offsets, while
//   arwsquadron_followPath advances independent path motion.
// - arwsquadron_emitEffects drives exhaust/muzzle effects, arwsquadron_updateVolley
//   schedules repeated shots, arwsquadron_spawnProjectile creates ARW projectile objects,
//   and arwsquadron_handleDamage handles hit reactions and arwing-controller callbacks.
//
// Descriptor slots:
// - 3: arwsquadron_init (0x80232D74)
// - 4: arwsquadron_update (0x80232830)
// - 5: arwsquadron_hitDetect (0x8023282C)
// - 6: arwsquadron_render (0x80232808)
// - 7: arwsquadron_free (0x80232804)
// - 8: arwsquadron_func08 (0x802327FC)
// - 9: arwsquadron_getExtraSize (0x802327F4)
// - helper: arwsquadron_emitEffects (0x80231A90)
// - helper: arwsquadron_applyCommandParams (0x80231C90)
// - helper: arwsquadron_followLeader (0x80231E30)
// - helper: arwsquadron_followPath (0x80232138)
// - helper: arwsquadron_spawnProjectile (0x80232278)
// - helper: arwsquadron_handleDamage (0x802323AC)
// - helper: arwsquadron_updateVolley (0x8023267C)
