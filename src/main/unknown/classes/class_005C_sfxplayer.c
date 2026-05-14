/*
 * Exploratory class packet for the retail-backed sfxPlayer class family.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a class-level recovery packet for early file-boundary work.
 *
 * Class ID: 0x005C
 * Reference class name: sfxPlayer
 * Suggested packet name: sfxPlayer
 * Output path: src/main/unknown/classes/class_005C_sfxplayer.c
 * Retail placements: 72
 * Retail object defs: 1
 * DLL IDs: 0x0133
 * Descriptor-backed DLL IDs: 0x0133
 * Retail root placement widths: 9w
 *
 * Retail object defs:
 * - 0x048F sfxPlayer: dll=0x0133, placements=72, widths=9w x72
 *
 * Descriptor slot maps:
 * - DLL 0x0133: gSfxPlayerObjDescriptor @ 0x803224A8 (slots=10, mask=0001100101)
 *   slot 03: 0x80198954 sfxplayerObj_init
 *   slot 04: 0x80198248 sfxplayerObj_update
 *   slot 07: 0x8019819C sfxplayerObj_free
 *   slot 09: 0x80198194 sfxplayerObj_getExtraSize
 */

#if 0
/*
 * Reference-only class packet enums. Verify against EN before promoting names into live code.
 */
enum class_005C_sfxPlayer_defs {
    SFXPLAYER_SFXPLAYER = 0x048F,
};
#endif
