/*
 * Reference-backed recovery packet.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a makeshift source-file boundary for object/DLL recovery work.
 *
 * DLL ID: 0x025E
 * Suggested family name: SpellStone
 * Output path: src/main/unknown/dll_025E_spellstone.c
 * EN descriptor: 0x8032A428 gSpellStoneObjDescriptor
 *
 * EN slot map with reference-backed names by slot index:
 * - slot 00: 0x80210E88 spellstone_initialise stub=blr ref=initialise (stub)
 * - slot 01: 0x80210E84 spellstone_release stub=blr ref=release (stub)
 * - slot 03: 0x80210E34 spellstone_init ref=init
 * - slot 04: 0x80210CC0 spellstone_update ref=update
 * - slot 05: 0x80210CBC spellstone_hitDetect stub=blr ref=hitDetect (stub)
 * - slot 06: 0x80210C7C spellstone_render ref=render
 * - slot 07: 0x80210C58 spellstone_free ref=free
 * - slot 08: 0x80210C50 spellstone_func08 stub=const 0
 * - slot 09: 0x80210C48 spellstone_getExtraSize stub=const 1 ref=getExtraSize (stub)
 * - slot 10: 0x80210C0C spellstone_setState ref=setState
 * - slot 11: 0x80210BF0 spellstone_getState ref=getState
 *
 * Reference-only hints:
 * - reference DLL name: SpellStone
 */

#if 0
enum dll_025E_SpellStone_slot {
    SPELLSTONE_INITIALISE = 0,
    SPELLSTONE_RELEASE = 1,
    SPELLSTONE_INIT = 3,
    SPELLSTONE_UPDATE = 4,
    SPELLSTONE_HITDETECT = 5,
    SPELLSTONE_RENDER = 6,
    SPELLSTONE_FREE = 7,
    SPELLSTONE_SLOT_08 = 8,
    SPELLSTONE_GETEXTRASIZE = 9,
    SPELLSTONE_SETSTATE = 10,
    SPELLSTONE_GETSTATE = 11,
};
#endif
