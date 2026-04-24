/*
 * Reference-backed recovery packet.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a makeshift source-file boundary for object/DLL recovery work.
 *
 * DLL ID: 0x0260
 * Suggested family name: ProximityMine
 * Output path: src/main/unknown/dll_0260_proximitymine.c
 * EN descriptor: 0x8032A4A0 gProximityMineObjDescriptor
 *
 * EN slot map with reference-backed names by slot index:
 * - slot 00: 0x80211C20 proximitymine_initialise stub=blr ref=initialise (stub)
 * - slot 01: 0x80211C1C proximitymine_release stub=blr ref=release (stub)
 * - slot 03: 0x80211A10 proximitymine_init ref=init
 * - slot 04: 0x802113F8 proximitymine_update ref=update
 * - slot 05: 0x8021133C proximitymine_hitDetect ref=hitDetect
 * - slot 06: 0x80211270 proximitymine_render ref=render
 * - slot 07: 0x8021123C proximitymine_free ref=free
 * - slot 08: 0x80211234 proximitymine_func08 stub=const 0
 * - slot 09: 0x8021122C proximitymine_getExtraSize stub=const 52 ref=getExtraSize (stub)
 *
 * Reference-only hints:
 * - reference DLL name: ProximityMine
 */

#if 0
enum dll_0260_ProximityMine_slot {
    PROXIMITYMINE_INITIALISE = 0,
    PROXIMITYMINE_RELEASE = 1,
    PROXIMITYMINE_INIT = 3,
    PROXIMITYMINE_UPDATE = 4,
    PROXIMITYMINE_HITDETECT = 5,
    PROXIMITYMINE_RENDER = 6,
    PROXIMITYMINE_FREE = 7,
    PROXIMITYMINE_SLOT_08 = 8,
    PROXIMITYMINE_GETEXTRASIZE = 9,
};
#endif
