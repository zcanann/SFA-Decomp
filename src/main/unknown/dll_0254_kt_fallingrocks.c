/*
 * Reference-backed recovery packet.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a makeshift source-file boundary for object/DLL recovery work.
 *
 * DLL ID: 0x0254
 * Suggested family name: KT_Fallingrocks
 * Output path: src/main/unknown/dll_0254_kt_fallingrocks.c
 * EN descriptor: 0x8032A678 gKtFallingrocksObjDescriptor
 *
 * Retail object defs:
 * - 0x0092 KT_Fallingr: def=0x03E8, class=0x0067, placements=1
 *
 * EN slot map with reference-backed names by slot index:
 * - slot 00: 0x80216EA8 ktfallingrocks_initialise stub=blr ref=initialise (stub)
 * - slot 01: 0x80216EA4 ktfallingrocks_release stub=blr ref=release (stub)
 * - slot 03: 0x80216E98 ktfallingrocks_init ref=init
 * - slot 04: 0x80216D68 ktfallingrocks_update ref=update
 * - slot 05: 0x80216D64 ktfallingrocks_hitDetect stub=blr ref=hitDetect (stub)
 * - slot 06: 0x80216D58 ktfallingrocks_render ref=render
 * - slot 07: 0x80216D28 ktfallingrocks_free ref=free
 * - slot 08: 0x80216D20 ktfallingrocks_func08 stub=const 0
 * - slot 09: 0x80216D18 ktfallingrocks_getExtraSize stub=const 0 ref=getExtraSize (stub)
 *
 * Reference-only hints:
 * - reference DLL name: KT_Fallingrocks
 */

#if 0
enum dll_0254_KT_Fallingrocks_slot {
    KTFALLINGROCKS_INITIALISE = 0,
    KTFALLINGROCKS_RELEASE = 1,
    KTFALLINGROCKS_INIT = 3,
    KTFALLINGROCKS_UPDATE = 4,
    KTFALLINGROCKS_HITDETECT = 5,
    KTFALLINGROCKS_RENDER = 6,
    KTFALLINGROCKS_FREE = 7,
    KTFALLINGROCKS_SLOT_08 = 8,
    KTFALLINGROCKS_GETEXTRASIZE = 9,
};
#endif
