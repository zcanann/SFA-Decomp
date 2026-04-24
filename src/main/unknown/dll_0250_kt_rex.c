/*
 * Reference-backed recovery packet.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a makeshift source-file boundary for object/DLL recovery work.
 *
 * DLL ID: 0x0250
 * Suggested family name: KT_Rex
 * Output path: src/main/unknown/dll_0250_kt_rex.c
 * EN descriptor: 0x8032A58C gKtRexObjDescriptor
 *
 * Retail object defs:
 * - 0x008A KT_Rex: def=0x03D9, class=0x006D, placements=1
 *
 * EN slot map with reference-backed names by slot index:
 * - slot 00: 0x8021590C ktrex_initialise ref=initialise
 * - slot 01: 0x80215908 ktrex_release stub=blr ref=release (stub)
 * - slot 03: 0x80215538 ktrex_init ref=init
 * - slot 04: 0x80215254 ktrex_update ref=update
 * - slot 05: 0x802151EC ktrex_hitDetect ref=hitDetect
 * - slot 06: 0x80214F20 ktrex_render ref=render
 * - slot 07: 0x80214E34 ktrex_free ref=free
 * - slot 08: 0x80214E2C ktrex_func08 stub=const 73
 * - slot 09: 0x80214E24 ktrex_getExtraSize stub=const 1444 ref=getExtraSize (stub)
 * - slot 10: 0x80214E14 ktrex_setScale ref=setScale
 * - slot 11: 0x80214E10 ktrex_func0B stub=blr
 *
 * Reference-only hints:
 * - reference DLL name: KT_Rex
 */

#if 0
enum dll_0250_KT_Rex_slot {
    KTREX_INITIALISE = 0,
    KTREX_RELEASE = 1,
    KTREX_INIT = 3,
    KTREX_UPDATE = 4,
    KTREX_HITDETECT = 5,
    KTREX_RENDER = 6,
    KTREX_FREE = 7,
    KTREX_SLOT_08 = 8,
    KTREX_GETEXTRASIZE = 9,
    KTREX_SETSCALE = 10,
    KTREX_SLOT_0B = 11,
};
#endif
