#ifndef MAIN_DLL_GRIMBLE_STATE_H_
#define MAIN_DLL_GRIMBLE_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/*
 * GrimbleControl - the grimble family's per-family control record (the
 * GroundBaddieState 'control' slot at +0x40C). The Grimble extra-size
 * callback allocates this complete 0x5C record after GroundBaddieState.
 */
typedef struct GrimbleControl {
    f32 posYDelta;
    f32 anchorPosY;
    f32 currentPosY;
    u8 pathState[0x1C - 0xC];
    f32 pathPosX;
    f32 pathPosY;
    f32 pathPosZ;
    u8 pad28[0x34 - 0x28];
    int candidatePathObj;
    int pathObj;
    f32 nearestDist;
    f32 candidateProgress;
    u8 unk44[0x45 - 0x44];
    s8 reversed;
    u8 unk46;
    u8 pad47;
    f32 pathProgress;
    f32 savedPathProgress;
    f32 unk50;
    f32 targetProgress;
    s16 baseRotX;
    u8 pad5A[2];
} GrimbleControl;

STATIC_ASSERT(sizeof(GrimbleControl) == 0x5C);
STATIC_ASSERT(offsetof(GrimbleControl, pathState) == 0x0C);
STATIC_ASSERT(offsetof(GrimbleControl, pathPosX) == 0x1C);
STATIC_ASSERT(offsetof(GrimbleControl, pathPosY) == 0x20);
STATIC_ASSERT(offsetof(GrimbleControl, pathPosZ) == 0x24);
STATIC_ASSERT(offsetof(GrimbleControl, candidatePathObj) == 0x34);
STATIC_ASSERT(offsetof(GrimbleControl, pathObj) == 0x38);
STATIC_ASSERT(offsetof(GrimbleControl, pathProgress) == 0x48);
STATIC_ASSERT(offsetof(GrimbleControl, targetProgress) == 0x54);
STATIC_ASSERT(offsetof(GrimbleControl, baseRotX) == 0x58);

#endif /* MAIN_DLL_GRIMBLE_STATE_H_ */
