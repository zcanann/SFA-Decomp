#ifndef MAIN_DLL_DLL_010B_FIREFLYLANTERN_H_
#define MAIN_DLL_DLL_010B_FIREFLYLANTERN_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"

typedef struct FireFlyLanternPlacement
{
    ObjPlacement base;
    u8 pad18;
    u8 mode; /* 0x19: 1 = single hidden-lantern firefly; otherwise a swarm */
    u8 pad1A[0xa];
} FireFlyLanternPlacement;

STATIC_ASSERT(offsetof(FireFlyLanternPlacement, mode) == 0x19);
STATIC_ASSERT(sizeof(FireFlyLanternPlacement) == 0x24);

typedef struct FireFlyLanternStateFlags
{
    u8 sequenceFinished : 1;
    u8 unused : 7;
} FireFlyLanternStateFlags;

typedef struct FireFlyLanternState
{
    GameObject* fireflies[7];
    u8 fireflyCount;
    u8 remainingCount;
    FireFlyLanternStateFlags flags;
    u8 pad1F;
    s16 countGameBit;
    u8 pad22[0x24 - 0x22];
} FireFlyLanternState;

STATIC_ASSERT(sizeof(FireFlyLanternStateFlags) == 0x1);
STATIC_ASSERT(sizeof(FireFlyLanternState) == 0x24);
STATIC_ASSERT(offsetof(FireFlyLanternState, fireflyCount) == 0x1C);
STATIC_ASSERT(offsetof(FireFlyLanternState, remainingCount) == 0x1D);
STATIC_ASSERT(offsetof(FireFlyLanternState, flags) == 0x1E);
STATIC_ASSERT(offsetof(FireFlyLanternState, countGameBit) == 0x20);

int FireFlyLantern_getExtraSize(void);
int FireFlyLantern_getObjectTypeId(void);
void FireFlyLantern_free(GameObject* obj);
void FireFlyLantern_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void FireFlyLantern_update(GameObject* obj);
void FireFlyLantern_init(GameObject* obj, FireFlyLanternPlacement* placement);
GameObject* FireFlyLantern_spawnFireFly(GameObject* obj);
int FireFlyLantern_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);

extern ObjectDescriptor gFireFlyLanternObjDescriptor;

#endif /* MAIN_DLL_DLL_010B_FIREFLYLANTERN_H_ */
