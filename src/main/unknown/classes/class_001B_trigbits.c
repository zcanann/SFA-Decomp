/*
 * Exploratory class packet for the retail-backed TrigBits class family.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a class-level recovery packet for early file-boundary work.
 *
 * Class ID: 0x001B
 * Reference class name: TrigBits
 * Suggested packet name: TrigBits
 * Output path: src/main/unknown/classes/class_001B_trigbits.c
 * Retail placements: 112
 * Retail object defs: 1
 * DLL IDs: 0x0126
 * Descriptor-backed DLL IDs: 0x0126
 * Retail object record sizes: 0xC0
 * Retail root placement widths: 20w
 *
 * Retail object defs:
 * - 0x0521 TrigBits: dll=0x0126, placements=112, romlists=19, objsize=0xC0, widths=20w x112, aliases=0x0054
 *
 * Descriptor slot maps:
 * - DLL 0x0126: gTriggerObjDescriptor (slots=10, mask=1101111111)
 *   slot 00: 0x8019AA78 Trigger_initialise
 *   slot 01: 0x8019AA74 Trigger_release
 *   slot 03: 0x8019A8A4 Trigger_init
 *   slot 04: 0x8019A8A0 Trigger_update
 *   slot 05: 0x8019A3B0 Trigger_hitDetect
 *   slot 06: 0x8019A3AC Trigger_render
 *   slot 07: 0x8019A310 Trigger_free
 *   slot 08: 0x8019A308 Trigger_getObjectTypeId
 *   slot 09: 0x8019A300 Trigger_getExtraSize
 */

#if 0
/*
 * Reference-only class packet enums. Verify against EN before promoting names into live code.
 */
enum class_001B_TrigBits_defs {
    TRIGBITS_TRIGBITS = 0x0521,
};
#endif
