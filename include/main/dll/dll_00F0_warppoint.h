#ifndef MAIN_DLL_DLL_00F0_WARPPOINT_H_
#define MAIN_DLL_DLL_00F0_WARPPOINT_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"

typedef struct WarpPointPlacement
{
    ObjPlacement base;
    u8 rotByte;
    s8 hintId;
    s8 warpMapIdx;
    s8 seqId;
    s8 enableFlag;
    s8 mode;
    s8 radiusByte;
    u8 savePointArmed;
    s16 gameBit;
    u8 pad22[0x28 - 0x22];
} WarpPointPlacement;

typedef struct WarpPointState
{
    s16 countdown;
    s16 gameBit;
    s16 seqId;
    s16 unk06;
    f32 triggerRadius;
    u8 triggered;
    u8 savePointRecorded;
    u8 pad0E[2];
} WarpPointState;

enum
{
    WARPPOINT_MODE_PROXIMITY = 0,
    WARPPOINT_MODE_HINT_TIMER = 1,
    WARPPOINT_MODE_GATED_WARP = 2,
    WARPPOINT_MODE_ONESHOT_SEQ = 3,
    WARPPOINT_MODE_GATED_WARP2 = 4
};

STATIC_ASSERT(sizeof(WarpPointPlacement) == 0x28);
STATIC_ASSERT(offsetof(WarpPointPlacement, mode) == 0x1D);
STATIC_ASSERT(offsetof(WarpPointPlacement, gameBit) == 0x20);
STATIC_ASSERT(sizeof(WarpPointState) == 0x10);
STATIC_ASSERT(offsetof(WarpPointState, triggerRadius) == 0x8);
STATIC_ASSERT(offsetof(WarpPointState, triggered) == 0xC);
STATIC_ASSERT(offsetof(WarpPointState, savePointRecorded) == 0xD);

int WarpPoint_animEventCallback(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int WarpPoint_getExtraSize(void);
int WarpPoint_getObjectTypeId(void);
void WarpPoint_render(GameObject* obj, int p1, int p2, int p3, int p4, s8 visible);
void WarpPoint_update(GameObject* obj);
void WarpPoint_init(GameObject* obj, WarpPointPlacement* placement);

extern ObjectDescriptor gWarpPointObjDescriptor;

#endif /* MAIN_DLL_DLL_00F0_WARPPOINT_H_ */
