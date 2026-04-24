/*
 * Reference-backed recovery packet.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a makeshift source-file boundary for object/DLL recovery work.
 *
 * DLL ID: 0x0253
 * Suggested family name: KT_Lazerlight
 * Output path: src/main/unknown/dll_0253_kt_lazerlight.c
 * EN descriptor: 0x8032A640 gKtLazerlightObjDescriptor
 *
 * Retail object defs:
 * - 0x0090 KT_Lazerlig: def=0x03E3, class=0x0030, placements=4
 *
 * EN slot map with reference-backed names by slot index:
 * - slot 00: 0x80216D14 ktlazerlight_initialise stub=blr ref=initialise (stub)
 * - slot 01: 0x80216D10 ktlazerlight_release stub=blr ref=release (stub)
 * - slot 03: 0x80216C98 ktlazerlight_init ref=init
 * - slot 04: 0x80216B90 ktlazerlight_update ref=update
 * - slot 05: 0x80216B8C ktlazerlight_hitDetect stub=blr ref=hitDetect (stub)
 * - slot 06: 0x80216B88 ktlazerlight_render stub=blr ref=render (stub)
 * - slot 07: 0x80216B58 ktlazerlight_free ref=free
 * - slot 08: 0x80216B50 ktlazerlight_func08 stub=const 0
 * - slot 09: 0x80216B48 ktlazerlight_getExtraSize stub=const 20 ref=getExtraSize (stub)
 *
 * Reference-only hints:
 * - reference DLL name: KT_Lazerlight
 */

#if 0
enum dll_0253_KT_Lazerlight_slot {
    KTLAZERLIGHT_INITIALISE = 0,
    KTLAZERLIGHT_RELEASE = 1,
    KTLAZERLIGHT_INIT = 3,
    KTLAZERLIGHT_UPDATE = 4,
    KTLAZERLIGHT_HITDETECT = 5,
    KTLAZERLIGHT_RENDER = 6,
    KTLAZERLIGHT_FREE = 7,
    KTLAZERLIGHT_SLOT_08 = 8,
    KTLAZERLIGHT_GETEXTRASIZE = 9,
};
#endif
