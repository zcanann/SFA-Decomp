#ifndef MAIN_DLL_DLL_02B0_BROKENPIPE_H
#define MAIN_DLL_DLL_02B0_BROKENPIPE_H

#include "global.h"
#include "main/game_object.h"

typedef struct BrokenPipeSetup
{
    ObjPlacement base;
    u8 rotZ;
    u8 rotY;
    u8 rotX;
    u8 scale;
    u8 pad1C[4];
} BrokenPipeSetup;

typedef struct BrokenPipeState
{
    f32 hitEffectCooldown;
} BrokenPipeState;

STATIC_ASSERT(offsetof(BrokenPipeSetup, rotZ) == 0x18);
STATIC_ASSERT(offsetof(BrokenPipeSetup, scale) == 0x1b);
STATIC_ASSERT(sizeof(BrokenPipeSetup) == 0x20);
STATIC_ASSERT(sizeof(BrokenPipeState) == 4);

extern f32 lbl_803E7338;
extern f32 lbl_803E733C;
extern f32 lbl_803E7340;

int brokenpipe_getExtraSize(void);
void brokenpipe_init(GameObject* obj, BrokenPipeSetup* setup);
void brokenpipe_update(GameObject* obj);

#endif
