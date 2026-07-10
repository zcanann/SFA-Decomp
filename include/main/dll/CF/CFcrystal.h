#ifndef MAIN_DLL_CF_CFCRYSTAL_H_
#define MAIN_DLL_CF_CFCRYSTAL_H_

#include "main/game_object.h"
#include "global.h"
#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

typedef struct FireFlyLanternSpawnSetup
{
    s16 objectType;
    u8 setupType;
    u8 pad03;
    u8 field04;
    u8 field05;
    u8 field06;
    u8 field07;
    f32 x;
    f32 y;
    f32 z;
    u8 pad14[0x18 - 0x14];
    u8 field18;
    u8 spawnMode; /* 0x19: 1 = single hidden-lantern firefly; else firefly swarm */
    s16 field1A;
    s16 field1C;
    u8 pad1E[0x24 - 0x1E];
} FireFlyLanternSpawnSetup;

STATIC_ASSERT(sizeof(FireFlyLanternSpawnSetup) == 0x24);
STATIC_ASSERT(offsetof(FireFlyLanternSpawnSetup, x) == 0x08);
STATIC_ASSERT(offsetof(FireFlyLanternSpawnSetup, field18) == 0x18);
STATIC_ASSERT(offsetof(FireFlyLanternSpawnSetup, spawnMode) == 0x19);
STATIC_ASSERT(offsetof(FireFlyLanternSpawnSetup, field1A) == 0x1A);
STATIC_ASSERT(offsetof(FireFlyLanternSpawnSetup, field1C) == 0x1C);

typedef struct FireFlyLanternState
{
    int fireflies[7];
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

#include "main/dll/CF/lanternfirefly_state.h"

extern ObjectDescriptor gLanternFireFlyObjDescriptor;
extern ObjectDescriptor gFireFlyLanternObjDescriptor;
extern ObjectDescriptor gFlammableVineObjDescriptor;

int LanternFireFly_getExtraSize(void);
int LanternFireFly_getObjectTypeId(void);
void LanternFireFly_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void LanternFireFly_hitDetect(void);
void LanternFireFly_update(GameObject* obj);
void LanternFireFly_init(GameObject* obj, int def);
void LanternFireFly_release(void);
void LanternFireFly_initialise(void);

int FireFlyLantern_getExtraSize(void);
int FireFlyLantern_getObjectTypeId(void);
void FireFlyLantern_free(int obj);
void FireFlyLantern_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void FireFlyLantern_update(GameObject* obj);
void FireFlyLantern_init(GameObject* param_1, int param_2);
int FireFlyLantern_spawnFireFly(int* obj);
int FireFlyLantern_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);

int FlammableVine_getExtraSize(void);
int FlammableVine_getObjectTypeId(void);
void FlammableVine_free(int obj);
void FlammableVine_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void FlammableVine_hitDetect(GameObject*);
void FlammableVine_update(GameObject*);
void FlammableVine_init(GameObject*);
void FlammableVine_release(void);
void FlammableVine_initialise(void);

#endif /* MAIN_DLL_CF_CFCRYSTAL_H_ */
