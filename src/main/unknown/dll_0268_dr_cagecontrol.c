/*
 * Reference-backed recovery packet.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a makeshift source-file boundary for object/DLL recovery work.
 *
 * DLL ID: 0x0268
 * Suggested family name: DR_CageControl
 * Output path: src/main/unknown/dll_0268_dr_cagecontrol.c
 * EN descriptor: 0x8032A8F8 gDrCageControlObjDescriptor
 *
 * EN slot map with reference-backed names by slot index:
 * - slot 00: 0x8021A428 cagecontrol_initialise stub=blr ref=initialise (stub)
 * - slot 01: 0x8021A424 cagecontrol_release stub=blr ref=release (stub)
 * - slot 03: 0x8021A3BC cagecontrol_init ref=init
 * - slot 04: 0x8021A290 cagecontrol_update ref=update
 * - slot 05: 0x8021A28C cagecontrol_hitDetect stub=blr ref=hitDetect (stub)
 * - slot 06: 0x8021A25C cagecontrol_render ref=render
 * - slot 07: 0x8021A258 cagecontrol_free stub=blr ref=free (stub)
 * - slot 08: 0x8021A250 cagecontrol_func08 stub=const 0
 * - slot 09: 0x8021A248 cagecontrol_getExtraSize stub=const 4 ref=getExtraSize (stub)
 *
 * Reference-only hints:
 * - reference DLL name: DR_CageControl
 */

#if 0
enum dll_0268_DR_CageControl_slot {
    CAGECONTROL_INITIALISE = 0,
    CAGECONTROL_RELEASE = 1,
    CAGECONTROL_INIT = 3,
    CAGECONTROL_UPDATE = 4,
    CAGECONTROL_HITDETECT = 5,
    CAGECONTROL_RENDER = 6,
    CAGECONTROL_FREE = 7,
    CAGECONTROL_SLOT_08 = 8,
    CAGECONTROL_GETEXTRASIZE = 9,
};
#endif
