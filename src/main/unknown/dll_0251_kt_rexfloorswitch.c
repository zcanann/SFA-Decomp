/*
 * Reference-backed recovery packet.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a makeshift source-file boundary for object/DLL recovery work.
 *
 * DLL ID: 0x0251
 * Suggested family name: KT_RexFloorSwitch
 * Output path: src/main/unknown/dll_0251_kt_rexfloorswitch.c
 * EN descriptor: 0x8032A5D0 gKtRexFloorSwitchObjDescriptor
 *
 * Retail object defs:
 * - 0x008E KT_RexFloor: def=0x03DD, class=0x006C, placements=8
 *
 * EN slot map with reference-backed names by slot index:
 * - slot 00: 0x802164CC ktrexfloorswitch_initialise stub=blr ref=initialise (stub)
 * - slot 01: 0x802164C8 ktrexfloorswitch_release stub=blr ref=release (stub)
 * - slot 03: 0x802163FC ktrexfloorswitch_init ref=init
 * - slot 04: 0x80215A84 ktrexfloorswitch_update ref=update
 * - slot 05: 0x80215A80 ktrexfloorswitch_hitDetect stub=blr ref=hitDetect (stub)
 * - slot 06: 0x80215A50 ktrexfloorswitch_render ref=render
 * - slot 07: 0x80215A4C ktrexfloorswitch_free stub=blr ref=free (stub)
 * - slot 08: 0x80215A44 ktrexfloorswitch_func08 stub=const 0
 * - slot 09: 0x80215A3C ktrexfloorswitch_getExtraSize stub=const 20 ref=getExtraSize (stub)
 *
 * Reference-only hints:
 * - reference DLL name: KT_RexFloorSwitch
 */

#if 0
enum dll_0251_KT_RexFloorSwitch_slot {
    KTREXFLOORSWITCH_INITIALISE = 0,
    KTREXFLOORSWITCH_RELEASE = 1,
    KTREXFLOORSWITCH_INIT = 3,
    KTREXFLOORSWITCH_UPDATE = 4,
    KTREXFLOORSWITCH_HITDETECT = 5,
    KTREXFLOORSWITCH_RENDER = 6,
    KTREXFLOORSWITCH_FREE = 7,
    KTREXFLOORSWITCH_SLOT_08 = 8,
    KTREXFLOORSWITCH_GETEXTRASIZE = 9,
};
#endif
