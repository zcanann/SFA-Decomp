#ifndef MAIN_DLL_KALDACHOM_STATE_H_
#define MAIN_DLL_KALDACHOM_STATE_H_

#include "ghidra_import.h"
#include "global.h"

typedef struct KaldaChomControl {
    void *spawnedDustObj;
    u8 unk04[0x10 - 0x04];
    f32 upperMouthPosX;
    f32 upperMouthPosY;
    f32 upperMouthPosZ;
    u8 unk1C[0x28 - 0x1C];
    f32 lowerMouthPosX;
    f32 lowerMouthPosY;
    f32 lowerMouthPosZ;
    f32 pullupSfxTimer;
    f32 idleAnimTimer;
    f32 unk3C;
    f32 hitFlashTimer;
    f32 returnStateTimer;
    s16 textureScrollAngle;
    u8 climbFxIndex;
    u8 soundFlags;
} KaldaChomControl;

STATIC_ASSERT(sizeof(KaldaChomControl) == 0x4C);
STATIC_ASSERT(offsetof(KaldaChomControl, pullupSfxTimer) == 0x34);
STATIC_ASSERT(offsetof(KaldaChomControl, hitFlashTimer) == 0x40);
STATIC_ASSERT(offsetof(KaldaChomControl, textureScrollAngle) == 0x48);
STATIC_ASSERT(offsetof(KaldaChomControl, soundFlags) == 0x4B);

#endif /* MAIN_DLL_KALDACHOM_STATE_H_ */
