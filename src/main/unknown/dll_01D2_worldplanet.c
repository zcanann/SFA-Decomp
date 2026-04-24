/*
 * Reference-backed recovery packet.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a makeshift source-file boundary for object/DLL recovery work.
 *
 * DLL ID: 0x01D2
 * Suggested family name: WORLDplanet
 * Output path: src/main/unknown/dll_01D2_worldplanet.c
 * EN descriptor: 0x8032A1C8 gWorldPlanetObjDescriptor
 *
 * Retail object defs:
 * - 0x0202 WORLDplanet: def=0x05D4, class=unknown, placements=unknown
 *
 * EN slot map with reference-backed names by slot index:
 * - slot 00: 0x8020D9E0 worldplanet_initialise stub=blr ref=initialise (stub)
 * - slot 01: 0x8020D9DC worldplanet_release stub=blr ref=release (stub)
 * - slot 03: 0x8020D7EC worldplanet_init ref=init
 * - slot 04: 0x8020C9CC worldplanet_update ref=update
 * - slot 05: 0x8020C9C8 worldplanet_hitDetect stub=blr ref=hitDetect (stub)
 * - slot 06: 0x8020C998 worldplanet_render ref=render
 * - slot 07: 0x8020C974 worldplanet_free ref=free
 * - slot 08: 0x8020C96C worldplanet_func08 stub=const 0
 * - slot 09: 0x8020C964 worldplanet_getExtraSize stub=const 24 ref=getExtraSize (stub)
 *
 * Reference-only hints:
 * - reference DLL name: WORLDplanet
 */

#if 0
enum dll_01D2_WORLDplanet_slot {
    WORLDPLANET_INITIALISE = 0,
    WORLDPLANET_RELEASE = 1,
    WORLDPLANET_INIT = 3,
    WORLDPLANET_UPDATE = 4,
    WORLDPLANET_HITDETECT = 5,
    WORLDPLANET_RENDER = 6,
    WORLDPLANET_FREE = 7,
    WORLDPLANET_SLOT_08 = 8,
    WORLDPLANET_GETEXTRASIZE = 9,
};
#endif
