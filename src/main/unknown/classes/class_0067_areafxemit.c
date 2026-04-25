/*
 * Exploratory class packet for the retail-backed AreaFXEmit class family.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a class-level recovery packet for early file-boundary work.
 *
 * Class ID: 0x0067
 * Reference class name: AreaFXEmit
 * Suggested packet name: AreaFXEmit
 * Output path: src/main/unknown/classes/class_0067_areafxemit.c
 * Retail placements: 58
 * Retail object defs: 4
 * DLL IDs: 0x0130 0x0181 0x0254
 * Descriptor-backed DLL IDs: 0x0130
 * Retail root placement widths: 10w
 *
 * Retail object defs:
 * - 0x05A8 AreaFXEmit: dll=0x0130, placements=35, widths=10w x35
 * - 0x05AA TAreaFXEmit: dll=0x0130, placements=21, widths=10w x21
 * - 0x0092 KT_Fallingr: dll=0x0254, placements=1, widths=10w x1
 * - 0x0263 MMP_trenchF: dll=0x0181, placements=1, widths=10w x1
 *
 * Descriptor slot maps:
 * - DLL 0x0130: gAreaFXEmitObjDescriptor @ 0x80321F80 (slots=10, mask=1101111111)
 *   slot 00: 0x8018FF24 areafxemit_initialise
 *   slot 01: 0x8018FF20 areafxemit_release
 *   slot 03: 0x8018FDD8 areafxemit_init
 *   slot 04: 0x8018FC50 areafxemit_update
 *   slot 05: 0x8018FC4C areafxemit_hitDetect
 *   slot 06: 0x8018FC40 areafxemit_render
 *   slot 07: 0x8018FC10 areafxemit_free
 *   slot 08: 0x8018FC08 areafxemit_func08
 *   slot 09: 0x8018FC00 areafxemit_getExtraSize
 */

#if 0
/*
 * Reference-only class packet enums. Verify against EN before promoting names into live code.
 */
enum class_0067_AreaFXEmit_defs {
    AREAFXEMIT_AREAFXEMIT = 0x05A8,
    AREAFXEMIT_TAREAFXEMIT = 0x05AA,
    AREAFXEMIT_KT_FALLINGR = 0x0092,
    AREAFXEMIT_MMP_TRENCHF = 0x0263,
};
#endif
