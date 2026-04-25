/*
 * Exploratory class packet for the retail-backed EffectBox class family.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a class-level recovery packet for early file-boundary work.
 *
 * Class ID: 0x0009
 * Reference class name: EffectBox
 * Suggested packet name: EffectBox
 * Output path: src/main/unknown/classes/class_0009_effectbox.c
 * Retail placements: 46
 * Retail object defs: 1
 * DLL IDs: 0x00EE
 * Descriptor-backed DLL IDs: 0x00EE
 * Retail root placement widths: 9w
 *
 * Retail object defs:
 * - 0x04D1 EffectBox: dll=0x00EE, placements=46, widths=9w x46
 *
 * Descriptor slot maps:
 * - DLL 0x00EE: gEffectBoxObjDescriptor @ 0x80320D10 (slots=10, mask=1101111111)
 *   slot 00: 0x80174434 effectbox_initialise
 *   slot 01: 0x80174430 effectbox_release
 *   slot 03: 0x801743B8 effectbox_init
 *   slot 04: 0x80173FE4 effectbox_update
 *   slot 05: 0x80173FE0 effectbox_hitDetect
 *   slot 06: 0x80173FB0 effectbox_render
 *   slot 07: 0x80173F90 effectbox_free
 *   slot 08: 0x80173F88 effectbox_func08
 *   slot 09: 0x80173F80 effectbox_getExtraSize
 */

#if 0
/*
 * Reference-only class packet enums. Verify against EN before promoting names into live code.
 */
enum class_0009_EffectBox_defs {
    EFFECTBOX_EFFECTBOX = 0x04D1,
};
#endif
