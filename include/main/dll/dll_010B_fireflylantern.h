#ifndef MAIN_DLL_DLL_010B_FIREFLYLANTERN_H_
#define MAIN_DLL_DLL_010B_FIREFLYLANTERN_H_

#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"

typedef struct FireFlyLanternSpawnSetup
{
    ObjPlacement base;
    u8 field18;
    u8 spawnMode; /* 0x19: 1 = single hidden-lantern firefly; else firefly swarm */
    s16 field1A;
    s16 field1C;
    u8 pad1E[0x24 - 0x1E];
} FireFlyLanternSpawnSetup;

STATIC_ASSERT(sizeof(FireFlyLanternSpawnSetup) == 0x24);
STATIC_ASSERT(offsetof(FireFlyLanternSpawnSetup, field18) == 0x18);
STATIC_ASSERT(offsetof(FireFlyLanternSpawnSetup, spawnMode) == 0x19);
STATIC_ASSERT(offsetof(FireFlyLanternSpawnSetup, field1A) == 0x1A);
STATIC_ASSERT(offsetof(FireFlyLanternSpawnSetup, field1C) == 0x1C);

typedef struct FireFlyLanternState
{
    GameObject* fireflies[7];
    u8 fireflyCount;
    u8 remainingCount;
    u8 flags;
    u8 pad1F;
    s16 gameBit;
    u8 pad22[0x24 - 0x22];
} FireFlyLanternState;

typedef struct FireFlyLanternStateFlags
{
    u8 finished : 1;
} FireFlyLanternStateFlags;

STATIC_ASSERT(sizeof(FireFlyLanternState) == 0x24);
STATIC_ASSERT(offsetof(FireFlyLanternState, fireflyCount) == 0x1C);
STATIC_ASSERT(offsetof(FireFlyLanternState, remainingCount) == 0x1D);
STATIC_ASSERT(offsetof(FireFlyLanternState, flags) == 0x1E);
STATIC_ASSERT(offsetof(FireFlyLanternState, gameBit) == 0x20);

int FireFlyLantern_getExtraSize(void);
int FireFlyLantern_getObjectTypeId(void);
void FireFlyLantern_free(GameObject* obj);
void FireFlyLantern_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void FireFlyLantern_update(GameObject* obj);
void FireFlyLantern_init(GameObject* obj, FireFlyLanternSpawnSetup* placement);
GameObject* FireFlyLantern_spawnFireFly(GameObject* obj);
int FireFlyLantern_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);

#endif /* MAIN_DLL_DLL_010B_FIREFLYLANTERN_H_ */
