#ifndef MAIN_DLL_DR_DLL_0283_DRBARRELGR_H
#define MAIN_DLL_DR_DLL_0283_DRBARRELGR_H

#include "global.h"
#include "main/dll/curve_walker.h"
#include "main/game_object.h"

typedef struct DrBarrelGrFlags
{
    u8 bit80 : 1;
    u8 bit40 : 1;
    u8 pad : 6;
} DrBarrelGrFlags;

typedef struct DrbarrelgrPlacement
{
    u8 pad0[0x18];
    s8 spawnYawByte;
    u8 speed;
    s16 range;
    u8 pad1C[0x20 - 0x1C];
    s16 gameBit;
    u8 pad22[0x28 - 0x22];
} DrbarrelgrPlacement;

typedef struct DrbarrelgrState
{
    s32 mode;
    s32 prevMode;
    s32 heldBarrel;
    u8 padC[0x10 - 0xC];
    f32 unk10;
    f32 grabX;
    f32 grabY;
    f32 grabZ;
    RomCurveWalker curve;
    s16 carrySpeed;
    u8 pad12A[0x12C - 0x12A];
} DrbarrelgrState;

STATIC_ASSERT(offsetof(DrbarrelgrState, heldBarrel) == 0x8);
STATIC_ASSERT(offsetof(DrbarrelgrState, grabX) == 0x14);
STATIC_ASSERT(offsetof(DrbarrelgrState, curve) == 0x20);
STATIC_ASSERT(offsetof(DrbarrelgrState, carrySpeed) == 0x128);
STATIC_ASSERT(sizeof(DrbarrelgrState) == 0x12C);

int DR_BarrelGr_getExtraSize(void);
int DR_BarrelGr_getObjectTypeId(void);
void DR_BarrelGr_free(GameObject* obj);
void DR_BarrelGr_render(GameObject* obj, int p2, int p3, int p4, int p5);
void DR_BarrelGr_hitDetect(void);
void DR_BarrelGr_update(GameObject* obj);
void DR_BarrelGr_init(GameObject* obj, int setup);
void DR_BarrelGr_release(void);
void DR_BarrelGr_initialise(void);

#endif
