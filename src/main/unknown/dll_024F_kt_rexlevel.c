/*
 * Reference-backed recovery packet.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a makeshift source-file boundary for object/DLL recovery work.
 *
 * DLL ID: 0x024F
 * Suggested family name: KT_RexLevel
 * Output path: src/main/unknown/dll_024F_kt_rexlevel.c
 * EN descriptor: 0x8032A4D8 gKtRexLevelObjDescriptor
 *
 * Retail object defs:
 * - 0x0089 KT_RexLevel: def=0x03D8, class=0x0039, placements=1
 *
 * EN slot map with reference-backed names by slot index:
 * - slot 00: 0x80211F34 ktrexlevel_initialise stub=blr ref=initialise (stub)
 * - slot 01: 0x80211F30 ktrexlevel_release stub=blr ref=release (stub)
 * - slot 03: 0x80211E6C ktrexlevel_init ref=init
 * - slot 04: 0x80211DC4 ktrexlevel_update ref=update
 * - slot 05: 0x80211CD4 ktrexlevel_hitDetect stub=blr ref=hitDetect (stub)
 * - slot 06: 0x80211CA4 ktrexlevel_render ref=render
 * - slot 07: 0x80211C34 ktrexlevel_free ref=free
 * - slot 08: 0x80211C2C ktrexlevel_func08 stub=const 0
 * - slot 09: 0x80211C24 ktrexlevel_getExtraSize stub=const 4 ref=getExtraSize (stub)
 *
 * Reference-only hints:
 * - reference DLL name: KT_RexLevel
 */

#if 0
enum dll_024F_KT_RexLevel_slot {
    KTREXLEVEL_INITIALISE = 0,
    KTREXLEVEL_RELEASE = 1,
    KTREXLEVEL_INIT = 3,
    KTREXLEVEL_UPDATE = 4,
    KTREXLEVEL_HITDETECT = 5,
    KTREXLEVEL_RENDER = 6,
    KTREXLEVEL_FREE = 7,
    KTREXLEVEL_SLOT_08 = 8,
    KTREXLEVEL_GETEXTRASIZE = 9,
};
#endif
