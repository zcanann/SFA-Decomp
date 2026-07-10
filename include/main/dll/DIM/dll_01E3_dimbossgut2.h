#ifndef MAIN_DLL_DIM_DLL_01E3_DIMBOSSGUT2_H_
#define MAIN_DLL_DIM_DLL_01E3_DIMBOSSGUT2_H_

#include "global.h"
#include "main/game_object.h"
#include "ghidra_import.h"

typedef struct Dimbossgut2State
{
    u8 pad0[0x4 - 0x0];
    s32 unk4;
    u8 pad8[0x3DC - 0x8];
    s32 curvePath; /* 0x3DC rom-curve path walker (Curve_AdvanceAlongPath/goNextPoint) */
    u8 pad3E0[0x400 - 0x3E0];
    u16 flags400; /* 0x400 bit3 = advancing along path */
    u8 pad402[0x40C - 0x402];
    s32 curveData; /* 0x40C Dimbossgut2Curve definition pointer */
    u8 pad410[0x42C - 0x410];
} Dimbossgut2State;

typedef struct Dimbossgut2Curve
{
    f32 f0;
    f32 f4;
    f32 f8;
    f32 fC;
    f32 f10;
    s16 s14;
    u16 timer16;
    s32 light;
} Dimbossgut2Curve;

STATIC_ASSERT(offsetof(Dimbossgut2Curve, f0) == 0x0);
STATIC_ASSERT(offsetof(Dimbossgut2Curve, f4) == 0x4);
STATIC_ASSERT(offsetof(Dimbossgut2Curve, f8) == 0x8);
STATIC_ASSERT(offsetof(Dimbossgut2Curve, fC) == 0xC);
STATIC_ASSERT(offsetof(Dimbossgut2Curve, f10) == 0x10);
STATIC_ASSERT(offsetof(Dimbossgut2Curve, s14) == 0x14);
STATIC_ASSERT(offsetof(Dimbossgut2Curve, timer16) == 0x16);
STATIC_ASSERT(offsetof(Dimbossgut2Curve, light) == 0x18);

void dimbossgut2_updateTracking(GameObject* obj, int state);
void DIM_BossGut2_func0B(void);
int DIM_BossGut2_setScale(void);
int DIM_BossGut2_getExtraSize(void);
int DIM_BossGut2_getObjectTypeId(void);
void DIM_BossGut2_free(int arg9);
void DIM_BossGut2_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void DIM_BossGut2_hitDetect(void);
void DIM_BossGut2_update(GameObject* obj);
void DIM_BossGut2_init(GameObject* obj, int def, int p3);
void DIM_BossGut2_release(void);
void DIM_BossGut2_initialise(void);

#endif /* MAIN_DLL_DIM_DLL_01E3_DIMBOSSGUT2_H_ */
