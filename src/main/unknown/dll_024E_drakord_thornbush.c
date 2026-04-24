/*
 * Reference-backed recovery packet.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a makeshift source-file boundary for object/DLL recovery work.
 *
 * DLL ID: 0x024E
 * Suggested family name: DrakorD_ThornBush
 * Output path: src/main/unknown/dll_024E_drakord_thornbush.c
 * EN descriptor: 0x8032A0D8 gDrakorDThornBushObjDescriptor
 *
 * Retail object defs:
 * - 0x0083 BossDrakorD: def=0x0709, class=0x0030, placements=0
 *
 * EN slot map with reference-backed names by slot index:
 * - slot 00: 0x8020C274 drakord_thornbush_initialise stub=blr ref=initialise (stub)
 * - slot 01: 0x8020C270 drakord_thornbush_release stub=blr ref=release (stub)
 * - slot 03: 0x8020C0A4 drakord_thornbush_init ref=init
 * - slot 04: 0x8020BE04 drakord_thornbush_update ref=update
 * - slot 05: 0x8020BBB0 drakord_thornbush_hitDetect ref=hitDetect
 * - slot 06: 0x8020BB1C drakord_thornbush_render ref=render
 * - slot 07: 0x8020BAC4 drakord_thornbush_free ref=free
 * - slot 08: 0x8020BABC drakord_thornbush_func08 stub=const 0
 * - slot 09: 0x8020BAB4 drakord_thornbush_getExtraSize stub=const 124 ref=getExtraSize (stub)
 *
 * Reference-only hints:
 * - reference DLL name: DrakorD_ThornBush
 */

#if 0
enum dll_024E_DrakorD_ThornBush_slot {
    DRAKORD_THORNBUSH_INITIALISE = 0,
    DRAKORD_THORNBUSH_RELEASE = 1,
    DRAKORD_THORNBUSH_INIT = 3,
    DRAKORD_THORNBUSH_UPDATE = 4,
    DRAKORD_THORNBUSH_HITDETECT = 5,
    DRAKORD_THORNBUSH_RENDER = 6,
    DRAKORD_THORNBUSH_FREE = 7,
    DRAKORD_THORNBUSH_SLOT_08 = 8,
    DRAKORD_THORNBUSH_GETEXTRASIZE = 9,
};
#endif
