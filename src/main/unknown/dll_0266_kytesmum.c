/*
 * Reference-backed recovery packet.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a makeshift source-file boundary for object/DLL recovery work.
 *
 * DLL ID: 0x0266
 * Suggested family name: KytesMum
 * Output path: src/main/unknown/dll_0266_kytesmum.c
 * EN descriptor: 0x8032A814 gKytesMumObjDescriptor
 *
 * Retail object defs:
 * - 0x0096 KytesMum: def=0x00BC, class=0x0030, placements=unknown
 *
 * EN slot map with reference-backed names by slot index:
 * - slot 00: 0x80219A84 kytesmum_initialise stub=blr ref=initialise (stub)
 * - slot 01: 0x80219A80 kytesmum_release stub=blr ref=release (stub)
 * - slot 03: 0x802198C0 kytesmum_init ref=init
 * - slot 04: 0x802195BC kytesmum_update ref=update
 * - slot 05: 0x802195B8 kytesmum_hitDetect stub=blr ref=hitDetect (stub)
 * - slot 06: 0x80219588 kytesmum_render ref=render
 * - slot 07: 0x80219550 kytesmum_free ref=free
 * - slot 08: 0x80219548 kytesmum_func08 stub=const 67
 * - slot 09: 0x80219540 kytesmum_getExtraSize stub=const 1772 ref=getExtraSize (stub)
 *
 * Reference-only hints:
 * - reference DLL name: KytesMum
 */

#if 0
enum dll_0266_KytesMum_slot {
    KYTESMUM_INITIALISE = 0,
    KYTESMUM_RELEASE = 1,
    KYTESMUM_INIT = 3,
    KYTESMUM_UPDATE = 4,
    KYTESMUM_HITDETECT = 5,
    KYTESMUM_RENDER = 6,
    KYTESMUM_FREE = 7,
    KYTESMUM_SLOT_08 = 8,
    KYTESMUM_GETEXTRASIZE = 9,
};
#endif
