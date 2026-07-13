#ifndef MAIN_DLL_DLL_019C_DLL19C_H_
#define MAIN_DLL_DLL_019C_DLL19C_H_

#include "main/game_object.h"

typedef struct Dll19CState
{
    u8 pad0[0x2 - 0x0];
    s16 unk2;
    s16 spawnTimer; /* 0x4: counts down by active*framesThisStep, spawns at <=0 */
    s16 active;     /* 0x6: 0/1 enables the spawn countdown */
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x2C - 0x14];
    s16 unk2C;
    s16 unk2E;
    s16 unk30;
    s16 unk32;
    u16 unk34;
    u8 unk36;
    u8 pad37[0x38 - 0x37];
} Dll19CState;

int dll_19C_getExtraSize(void);
int dll_19C_getObjectTypeId(void);
void dll_19C_free(void);
void dll_19C_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dll_19C_hitDetect(void);
void dll_19C_update(int* obj);
void dll_19C_init(GameObject* obj, u8* initData);
void dll_19C_release(void);
void dll_19C_initialise(void);

#endif /* MAIN_DLL_DLL_019C_DLL19C_H_ */
