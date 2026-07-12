#ifndef MAIN_DLL_ARW_DLL_02A2_ARWSPEEDSTR_H
#define MAIN_DLL_ARW_DLL_02A2_ARWSPEEDSTR_H

#include "global.h"
#include "main/game_object.h"

typedef struct ARWSpeedStrState
{
    f32 speed;
    f32 lifeTimer;
    f32 alpha;
    f32 spreadX;
    f32 spreadY;
    f32 viewZ;
    u8 flags;
    u8 pad19[3];
} ARWSpeedStrState;

typedef struct ARWSpeedStrVelocity
{
    f32 x;
    f32 y;
    f32 z;
} ARWSpeedStrVelocity;

STATIC_ASSERT(sizeof(ARWSpeedStrState) == 0x1c);
STATIC_ASSERT(offsetof(ARWSpeedStrState, speed) == 0x00);
STATIC_ASSERT(offsetof(ARWSpeedStrState, lifeTimer) == 0x04);
STATIC_ASSERT(offsetof(ARWSpeedStrState, alpha) == 0x08);
STATIC_ASSERT(offsetof(ARWSpeedStrState, spreadX) == 0x0c);
STATIC_ASSERT(offsetof(ARWSpeedStrState, spreadY) == 0x10);
STATIC_ASSERT(offsetof(ARWSpeedStrState, viewZ) == 0x14);
STATIC_ASSERT(offsetof(ARWSpeedStrState, flags) == 0x18);
STATIC_ASSERT(offsetof(ARWSpeedStrVelocity, x) == 0x00);
STATIC_ASSERT(offsetof(ARWSpeedStrVelocity, y) == 0x04);
STATIC_ASSERT(offsetof(ARWSpeedStrVelocity, z) == 0x08);

extern f32 lbl_803E7100;
extern f32 lbl_803E7104;
extern f32 lbl_803E7108;
extern f32 lbl_803E710C;

int ARWSpeedStr_getExtraSize(void);
int ARWSpeedStr_getObjectTypeId(void);
void ARWSpeedStr_free(void);
void ARWSpeedStr_hitDetect(void);
void ARWSpeedStr_render(int obj, int p2, int p3, int p4, int p5, f32 scale);
void ARWSpeedStr_init(GameObject* obj, int setup);
void ARWSpeedStr_update(GameObject* obj);
void ARWSpeedStr_release(void);
void ARWSpeedStr_initialise(void);

void fn_80231028(GameObject* obj, int speed);
void fn_80231058(GameObject* obj, int src);

#endif
