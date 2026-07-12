#ifndef MAIN_DLL_DR_DLL_0283_DRBARRELGR_H
#define MAIN_DLL_DR_DLL_0283_DRBARRELGR_H

#include "global.h"
#include "main/dll/curve_walker.h"
#include "main/game_object.h"

extern f32 lbl_803E6CA0;
extern f32 lbl_803E6CA4;
extern f32 lbl_803E6CA8;
extern f32 lbl_803E6CAC;
extern f32 gDrBarrelGenGrabRange;
extern f32 lbl_803E6CB4;
extern f32 gDrBarrelGenCarrySpeedScale;
extern f32 lbl_803E6CBC;
extern f32 lbl_803E6CC0;
extern f32 lbl_803E6CD0;
extern f32 lbl_803DC3B0;
extern f32 gDrBarrelGenGrabYOffset;

typedef struct DrBarrelGrRenderParams
{
    s16 a;
    s16 b;
    s16 c;
    f32 d;
} DrBarrelGrRenderParams;

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
    GameObject* heldBarrel;
    f32 timer;
    f32 unk10;
    f32 grabX;
    f32 grabY;
    f32 grabZ;
    RomCurveWalker curve;
    s16 carrySpeed;
    DrBarrelGrFlags flags;
    u8 pad12B;
} DrbarrelgrState;

STATIC_ASSERT(offsetof(DrbarrelgrState, heldBarrel) == 0x8);
STATIC_ASSERT(offsetof(DrbarrelgrState, timer) == 0xc);
STATIC_ASSERT(offsetof(DrbarrelgrState, grabX) == 0x14);
STATIC_ASSERT(offsetof(DrbarrelgrState, curve) == 0x20);
STATIC_ASSERT(offsetof(DrbarrelgrState, carrySpeed) == 0x128);
STATIC_ASSERT(offsetof(DrbarrelgrState, flags) == 0x12a);
STATIC_ASSERT(sizeof(DrbarrelgrState) == 0x12C);

int DR_BarrelGr_getExtraSize(void);
int DR_BarrelGr_getObjectTypeId(void);
void DR_BarrelGr_free(GameObject* obj);
void DR_BarrelGr_render(GameObject* obj, int p2, int p3, int p4, int p5);
void DR_BarrelGr_hitDetect(void);
void DR_BarrelGr_update(GameObject* obj);
void DR_BarrelGr_init(GameObject* obj, DrbarrelgrPlacement* setup);
void DR_BarrelGr_release(void);
void DR_BarrelGr_initialise(void);

#endif
