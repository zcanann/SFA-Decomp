/*
 * Exploratory class packet for the retail-backed StaffActivated class family.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a class-level recovery packet for early file-boundary work.
 *
 * Class ID: 0x007A
 * Reference class name: StaffActivated
 * Suggested packet name: StaffActivated
 * Output path: src/main/unknown/classes/class_007A_staffactivated.c
 * Retail placements: 115
 * Retail object defs: 8
 * DLL IDs: 0x011C
 * Descriptor-backed DLL IDs: 0x011C
 * Retail root placement widths: 10w
 *
 * Retail object defs:
 * - 0x05B1 StaffLeverO: dll=0x011C, placements=40, widths=10w x40
 * - 0x05AD StaffBoostP: dll=0x011C, placements=29, widths=10w x29
 * - 0x05AE StaffBoulde: dll=0x011C, placements=21, widths=10w x21
 * - 0x05B2 StaffLeverT: dll=0x011C, placements=13, widths=10w x13
 * - 0x05AF StaffBoulde: dll=0x011C, placements=8, widths=10w x8
 * - 0x05B0 StaffBoulde: dll=0x011C, placements=3, widths=10w x3
 * - 0x01D5 LINKStaffLe: dll=0x011C, placements=1, widths=10w x1
 * - 0x05AC StaffAction: dll=0x011C, placements=0, widths=none
 *
 * Descriptor slot maps:
 * - DLL 0x011C: gStaffActivatedObjDescriptor @ 0x80321C28 (slots=10, mask=0001101111)
 *   slot 03: 0x8018A53C staffactivated_init
 *   slot 04: 0x8018A284 staffactivated_update
 *   slot 06: 0x8018A260 staffactivated_render
 *   slot 07: 0x8018A23C staffactivated_free
 *   slot 08: 0x8018A234 staffactivated_func08
 *   slot 09: 0x8018A22C staffactivated_getExtraSize
 */

#if 0
/*
 * Reference-only class packet enums. Verify against EN before promoting names into live code.
 */
enum class_007A_StaffActivated_defs {
    STAFFACTIVATED_STAFFLEVERO = 0x05B1,
    STAFFACTIVATED_STAFFBOOSTP = 0x05AD,
    STAFFACTIVATED_STAFFBOULDE_05AE = 0x05AE,
    STAFFACTIVATED_STAFFLEVERT = 0x05B2,
    STAFFACTIVATED_STAFFBOULDE_05AF = 0x05AF,
    STAFFACTIVATED_STAFFBOULDE_05B0 = 0x05B0,
    STAFFACTIVATED_LINKSTAFFLE = 0x01D5,
    STAFFACTIVATED_STAFFACTION = 0x05AC,
};
#endif
