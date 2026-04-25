/*
 * Exploratory class packet for the retail-backed warp class family.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a class-level recovery packet for early file-boundary work.
 *
 * Class ID: 0x0025
 * Reference class name: warp
 * Suggested packet name: warp
 * Output path: src/main/unknown/classes/class_0025_warp.c
 * Retail placements: 83
 * Retail object defs: 7
 * DLL IDs: 0x00F0 0x012C
 * Descriptor-backed DLL IDs: 0x00F0 0x012C
 * Retail root placement widths: 9w
 *
 * Retail object defs:
 * - 0x04B2 WarpPoint: dll=0x00F0, placements=43, widths=9w x43
 * - 0x04B1 Transporter: dll=0x012C, placements=33, widths=9w x33
 * - 0x02C3 KP_Transpor: dll=0x012C, placements=2, widths=9w x2
 * - 0x02D2 SC_warppoin: dll=0x00F0, placements=2, widths=9w x2
 * - 0x04B3 RestartPoin: dll=0x00F0, placements=2, widths=9w x2
 * - 0x0259 MMP_WarpPoi: dll=0x00F0, placements=1, widths=9w x1
 * - 0x0397 WM_WarpPoin: dll=0x00F0, placements=0, widths=none
 *
 * Descriptor slot maps:
 * - DLL 0x00F0: gWarpPointObjDescriptor @ 0x80321A08 (slots=10, mask=0001101011)
 *   slot 03: 0x80177B6C warppoint_init
 *   slot 04: 0x8017750C warppoint_update
 *   slot 06: 0x801774EC warppoint_render
 *   slot 08: 0x801774E4 warppoint_func08
 *   slot 09: 0x801774DC warppoint_getExtraSize
 * - DLL 0x012C: gTransporterObjDescriptor @ 0x80321FF8 (slots=10, mask=0001111001)
 *   slot 03: 0x801916A0 transporter_init
 *   slot 04: 0x80191658 transporter_update
 *   slot 05: 0x801914AC transporter_hitDetect
 *   slot 06: 0x801914A8 transporter_render
 *   slot 09: 0x801914A0 transporter_getExtraSize
 */

#if 0
/*
 * Reference-only class packet enums. Verify against EN before promoting names into live code.
 */
enum class_0025_warp_defs {
    WARP_WARPPOINT = 0x04B2,
    WARP_TRANSPORTER = 0x04B1,
    WARP_KP_TRANSPOR = 0x02C3,
    WARP_SC_WARPPOIN = 0x02D2,
    WARP_RESTARTPOIN = 0x04B3,
    WARP_MMP_WARPPOI = 0x0259,
    WARP_WM_WARPPOIN = 0x0397,
};
#endif
