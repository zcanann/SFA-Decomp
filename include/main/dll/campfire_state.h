#ifndef MAIN_DLL_CAMPFIRE_STATE_H_
#define MAIN_DLL_CAMPFIRE_STATE_H_

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

/* campfire_state_GENERATED
 * CampfireState - the obj+0xB8 extra record observed in campfire.c. Field widths
 * mirror the observed deref widths; unobserved ranges are padded. The
 * span covers every observed access - the true allocation may be larger.
 */
typedef struct CampfireState {
    u8 unk0[0x270 - 0x0];
    s16 unk270;
    u8 unk272[0x274 - 0x272];
    s16 controlMode;
    u8 unk276[0x2D0 - 0x276];
    int targetObj;
    u8 unk2D4[0x3F4 - 0x2D4];
    s16 gameBitB;
    u8 unk3F6[0x3FE - 0x3F6];
    u16 aggroRange;
    u8 unk400[0x402 - 0x400];
    s16 targetState;
    u8 unk404[0x40C - 0x404];
    KaldaChomControl *control;
    KaldaChomControl controlData;
} CampfireState;

STATIC_ASSERT(sizeof(KaldaChomControl) == 0x4C);
STATIC_ASSERT(offsetof(KaldaChomControl, pullupSfxTimer) == 0x34);
STATIC_ASSERT(offsetof(KaldaChomControl, hitFlashTimer) == 0x40);
STATIC_ASSERT(offsetof(KaldaChomControl, textureScrollAngle) == 0x48);
STATIC_ASSERT(offsetof(KaldaChomControl, soundFlags) == 0x4B);
STATIC_ASSERT(offsetof(CampfireState, controlData) == 0x410);
STATIC_ASSERT(sizeof(CampfireState) == 0x45C);

#endif /* MAIN_DLL_CAMPFIRE_STATE_H_ */
