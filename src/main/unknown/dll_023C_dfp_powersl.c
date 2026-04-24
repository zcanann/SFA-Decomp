/*
 * Reference-backed recovery packet.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a makeshift source-file boundary for object/DLL recovery work.
 *
 * DLL ID: 0x023C
 * Suggested family name: DFP_PowerSl
 * Output path: src/main/unknown/dll_023C_dfp_powersl.c
 * EN descriptor: 0x80329E08 gDfppowerslObjDescriptor
 *
 * Retail object defs:
 * - 0x0344 DFP_PowerSl: def=0x082F, class=0x0030, placements=0
 *
 * EN slot map with reference-backed names by slot index:
 * - slot 03: 0x8020A130 dfppowersl_init ref=init
 * - slot 04: 0x8020A0C4 dfppowersl_update ref=update
 * - slot 06: 0x8020A020 dfppowersl_render ref=render
 * - slot 07: 0x80209FE8 dfppowersl_free ref=free
 * - slot 09: 0x80209FE0 dfppowersl_getExtraSize stub=const 12 ref=getExtraSize (stub)
 *
 * Reference-only hints:
 * - reference DLL name: DFP_PowerSl
 */

#if 0
enum dll_023C_DFP_PowerSl_slot {
    DFP_POWERSL_INIT = 3,
    DFP_POWERSL_UPDATE = 4,
    DFP_POWERSL_RENDER = 6,
    DFP_POWERSL_FREE = 7,
    DFP_POWERSL_GETEXTRASIZE = 9,
};
#endif
