/*
 * Reference-backed recovery packet.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a makeshift source-file boundary for object/DLL recovery work.
 *
 * DLL ID: 0x025D
 * Suggested family name: CRCloudRace
 * Output path: src/main/unknown/dll_025D_crcloudrace.c
 * EN descriptor: 0x8032A3C8 gCrCloudRaceObjDescriptor
 *
 * Retail object defs:
 * - 0x0108 CRCloudRace: def=0x038B, class=0x0039, placements=unknown
 *
 * EN slot map with reference-backed names by slot index:
 * - slot 00: 0x80210BE4 crcloudrace_initialise stub=blr ref=initialise (stub)
 * - slot 01: 0x80210BE0 crcloudrace_release stub=blr ref=release (stub)
 * - slot 03: 0x80210B88 crcloudrace_init ref=init
 * - slot 04: 0x80210A9C crcloudrace_update ref=update
 * - slot 05: 0x80210A98 crcloudrace_hitDetect stub=blr ref=hitDetect (stub)
 * - slot 06: 0x80210A68 crcloudrace_render ref=render
 * - slot 07: 0x80210A64 crcloudrace_free stub=blr ref=free (stub)
 * - slot 08: 0x80210A5C crcloudrace_func08 stub=const 0
 * - slot 09: 0x80210A54 crcloudrace_getExtraSize stub=const 16 ref=getExtraSize (stub)
 *
 * Reference-only hints:
 * - reference DLL name: CRCloudRace
 */

#if 0
enum dll_025D_CRCloudRace_slot {
    CRCLOUDRACE_INITIALISE = 0,
    CRCLOUDRACE_RELEASE = 1,
    CRCLOUDRACE_INIT = 3,
    CRCLOUDRACE_UPDATE = 4,
    CRCLOUDRACE_HITDETECT = 5,
    CRCLOUDRACE_RENDER = 6,
    CRCLOUDRACE_FREE = 7,
    CRCLOUDRACE_SLOT_08 = 8,
    CRCLOUDRACE_GETEXTRASIZE = 9,
};
#endif
