/*
 * Reference-backed recovery packet.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a makeshift source-file boundary for object/DLL recovery work.
 *
 * DLL ID: 0x025C
 * Suggested family name: SnowClaw
 * Output path: src/main/unknown/dll_025C_snowclaw.c
 * EN descriptor: 0x8032A370 gSnowClawObjDescriptor
 *
 * Retail object defs:
 * - 0x010A CRSnowClaw: def=0x0389, class=0x001C, placements=unknown
 * - 0x010B CRSnowClaw2: def=0x038A, class=0x001C, placements=unknown
 * - 0x010C CRSnowClaw3: def=0x04D3, class=0x001C, placements=unknown
 * - 0x01C0 IMSnowClaw: def=0x016D, class=0x001C, placements=unknown
 * - 0x01C1 IMSnowClaw2: def=0x0170, class=0x001C, placements=unknown
 *
 * EN slot map with reference-backed names by slot index:
 * - slot 00: 0x802106BC snowclaw_initialise stub=blr ref=initialise (stub)
 * - slot 01: 0x802106B8 snowclaw_release stub=blr ref=release (stub)
 * - slot 03: 0x80210558 snowclaw_init ref=init
 * - slot 04: 0x80210134 snowclaw_update ref=update
 * - slot 05: 0x8020FDB0 snowclaw_hitDetect ref=hitDetect
 * - slot 06: 0x8020FB2C snowclaw_render ref=render
 * - slot 07: 0x8020FB00 snowclaw_free ref=free
 * - slot 08: 0x8020FAF8 snowclaw_func08 stub=const 3
 * - slot 09: 0x8020FAF0 snowclaw_getExtraSize stub=const 176 ref=getExtraSize (stub)
 *
 * Reference-only hints:
 * - reference DLL name: SnowClaw
 */

#if 0
enum dll_025C_SnowClaw_slot {
    SNOWCLAW_INITIALISE = 0,
    SNOWCLAW_RELEASE = 1,
    SNOWCLAW_INIT = 3,
    SNOWCLAW_UPDATE = 4,
    SNOWCLAW_HITDETECT = 5,
    SNOWCLAW_RENDER = 6,
    SNOWCLAW_FREE = 7,
    SNOWCLAW_SLOT_08 = 8,
    SNOWCLAW_GETEXTRASIZE = 9,
};
#endif
