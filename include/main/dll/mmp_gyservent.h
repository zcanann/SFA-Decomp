#ifndef MAIN_DLL_MMP_GYSERVENT_H_
#define MAIN_DLL_MMP_GYSERVENT_H_

#include "global.h"
#include "main/game_object.h"

typedef struct MmpGyserventState
{
    u8 pad0[0x4 - 0x0];
    f32 nearRadiusSq; /* 0x04: squared near-distance threshold */
    u8 pad8[0xC - 0x8];
    f32 planeNormalX; /* 0x0C: clip-plane normal (vent local forward) */
    f32 planeNormalY; /* 0x10 */
    f32 planeNormalZ; /* 0x14 */
    f32 planeOffset;  /* 0x18: plane d term */
    f32 reachAX;      /* 0x1C: reach endpoint A */
    f32 reachAY;      /* 0x20 */
    f32 reachAZ;      /* 0x24 */
    f32 reachBX;      /* 0x28: reach endpoint B */
    f32 reachBY;      /* 0x2C */
    f32 reachBZ;      /* 0x30 */
    f32 reach;        /* 0x34: eruption reach distance */
} MmpGyserventState;

STATIC_ASSERT(offsetof(MmpGyserventState, nearRadiusSq) == 0x04);
STATIC_ASSERT(offsetof(MmpGyserventState, planeNormalX) == 0x0C);
STATIC_ASSERT(offsetof(MmpGyserventState, planeOffset) == 0x18);
STATIC_ASSERT(offsetof(MmpGyserventState, reachAX) == 0x1C);
STATIC_ASSERT(offsetof(MmpGyserventState, reachBX) == 0x28);
STATIC_ASSERT(offsetof(MmpGyserventState, reach) == 0x34);

void objFn_80198fa4(s16* obj, void* placement);
void objSeqMoveFn_80199188(GameObject* obj, int arg2);
void objSeqFn_801992ec(GameObject* obj, int arg2);

#endif /* MAIN_DLL_MMP_GYSERVENT_H_ */
