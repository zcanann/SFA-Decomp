#ifndef MAIN_OBJ_PLACEMENT_H_
#define MAIN_OBJ_PLACEMENT_H_

#include "global.h"

/*
 * ObjPlacement - the COMMON HEAD of the per-object placement/setup
 * record at obj+0x4C (ObjAnimComponent.placementData). Cross-partition
 * census (engine: objseq.c/main.c/light.c; dll root: 47 TUs):
 *  - 0x00/0x02 s16 pair: CLASS-DEPENDENT. player.c's arwprojectile
 *    setup writes a yaw/pitch pair ((s16)getAngle(dx,dz) at +0,
 *    -getAngle(dy,horiz) at +2), but main.c's trigger path reads +2 as
 *    a GameBit id - so the slots are rotation-by-convention, repurposed
 *    per class. Kept as unk00/unk02 until a single semantic holds.
 *  - 0x04..0x07 u8[4]: RGBA tint applied to the spawned object/effect
 *    (color[0..2] = R/G/B, color[3] = alpha). 15 dll spawn-setup TUs
 *    write it as a 4-byte color block; alpha often biased down to fade.
 *  - 0x08/0x0C/0x10 f32: placement position (187/350/178 dll sites +
 *    engine consensus)
 *  - 0x14 s32 mapId: 157 dll sites; name follows the established
 *    TexScrollPlacement convention (mmp_moonrock.h)
 * Everything from 0x18 on is class-specific - per-family
 * <Family>Placement structs carry those fields, either by embedding
 * this head (struct { ObjPlacement head; ... }) or by mirroring with
 * pads to 0x18 like TexScrollPlacement does; both are layout-identical.
 *
 * Do NOT retype ObjAnimComponent.placementData to ObjPlacement* - its
 * s16* deref width is load-bearing at placementData[i] sites; carry the
 * typed view in per-TU locals/params instead. With int-typed bases use
 * the typed-local form, not per-site casts (per-site int->ptr casts
 * materialize member address temps).
 */
typedef struct ObjPlacement {
    u8 unk00[2];
    s16 unk02;
    u8 color[4];
    f32 posX;
    f32 posY;
    f32 posZ;
    s32 mapId;
} ObjPlacement;

STATIC_ASSERT(offsetof(ObjPlacement, posX) == 0x8);
STATIC_ASSERT(offsetof(ObjPlacement, mapId) == 0x14);
STATIC_ASSERT(sizeof(ObjPlacement) == 0x18);

#endif
