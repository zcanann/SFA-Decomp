/*
 * Exploratory class packet for the retail-backed TrigCyl class family.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a class-level recovery packet for early file-boundary work.
 *
 * Class ID: 0x0016
 * Reference class name: TrigCyl
 * Suggested packet name: TrigCyl
 * Output path: src/main/unknown/classes/class_0016_trigcyl.c
 * Retail placements: 56
 * Retail object defs: 1
 * DLL IDs: 0x0126
 * Descriptor-backed DLL IDs: 0x0126
 * Retail object record sizes: 0xA0
 * Retail root placement widths: 20w
 *
 * Retail object defs:
 * - 0x051B TrigCyl: dll=0x0126, placements=56, romlists=14, objsize=0xA0, widths=20w x56, aliases=0x0230
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
enum class_0016_TrigCyl_defs {
    TRIGCYL_TRIGCYL = 0x051B,
};
#endif
