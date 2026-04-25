/*
 * Exploratory class packet for the retail-backed FXEmit class family.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a class-level recovery packet for early file-boundary work.
 *
 * Class ID: 0x006B
 * Reference class name: FXEmit
 * Suggested packet name: FXEmit
 * Output path: src/main/unknown/classes/class_006B_fxemit.c
 * Retail placements: 189
 * Retail object defs: 2
 * DLL IDs: 0x012B 0x01E6
 * Descriptor-backed DLL IDs: 0x012B
 * Retail root placement widths: 11w
 *
 * Retail object defs:
 * - 0x05A7 FXEmit: dll=0x012B, placements=189, widths=11w x189
 * - 0x0076 DIMbosscrac: dll=0x01E6, placements=0, widths=none
 *
 * Descriptor slot maps:
 * - DLL 0x012B: gFXEmitObjDescriptor @ 0x80321F38 (slots=10, mask=1101111111)
 *   slot 00: 0x8018F144 fxemit_initialise
 *   slot 01: 0x8018F140 fxemit_release
 *   slot 03: 0x8018EFE0 fxemit_init
 *   slot 04: 0x8018EC98 fxemit_update
 *   slot 05: 0x8018EC94 fxemit_hitDetect
 *   slot 06: 0x8018EC88 fxemit_render
 *   slot 07: 0x8018EC34 fxemit_free
 *   slot 08: 0x8018EC2C fxemit_func08
 *   slot 09: 0x8018EC24 fxemit_getExtraSize
 */

#if 0
/*
 * Reference-only class packet enums. Verify against EN before promoting names into live code.
 */
enum class_006B_FXEmit_defs {
    FXEMIT_FXEMIT = 0x05A7,
    FXEMIT_DIMBOSSCRAC = 0x0076,
};
#endif
