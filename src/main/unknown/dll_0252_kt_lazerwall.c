/*
 * Reference-backed recovery packet.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a makeshift source-file boundary for object/DLL recovery work.
 *
 * DLL ID: 0x0252
 * Suggested family name: KT_Lazerwall
 * Output path: src/main/unknown/dll_0252_kt_lazerwall.c
 * EN descriptor: 0x8032A608 gKtLazerwallObjDescriptor
 *
 * Retail object defs:
 * - 0x008F KT_Lazerwal: def=0x03E0, class=0x0030, placements=16
 *
 * EN slot map with reference-backed names by slot index:
 * - slot 00: 0x80216B44 ktlazerwall_initialise stub=blr ref=initialise (stub)
 * - slot 01: 0x80216B40 ktlazerwall_release stub=blr ref=release (stub)
 * - slot 03: 0x80216AA8 ktlazerwall_init ref=init
 * - slot 04: 0x80216798 ktlazerwall_update ref=update
 * - slot 05: 0x80216794 ktlazerwall_hitDetect stub=blr ref=hitDetect (stub)
 * - slot 06: 0x80216670 ktlazerwall_render ref=render
 * - slot 07: 0x80216630 ktlazerwall_free ref=free
 * - slot 08: 0x80216628 ktlazerwall_func08 stub=const 0
 * - slot 09: 0x80216620 ktlazerwall_getExtraSize stub=const 20 ref=getExtraSize (stub)
 *
 * Reference-only hints:
 * - reference DLL name: KT_Lazerwall
 */

#if 0
enum dll_0252_KT_Lazerwall_slot {
    KTLAZERWALL_INITIALISE = 0,
    KTLAZERWALL_RELEASE = 1,
    KTLAZERWALL_INIT = 3,
    KTLAZERWALL_UPDATE = 4,
    KTLAZERWALL_HITDETECT = 5,
    KTLAZERWALL_RENDER = 6,
    KTLAZERWALL_FREE = 7,
    KTLAZERWALL_SLOT_08 = 8,
    KTLAZERWALL_GETEXTRASIZE = 9,
};
#endif
