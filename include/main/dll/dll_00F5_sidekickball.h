#ifndef MAIN_DLL_DLL_00F5_SIDEKICKBALL_H_
#define MAIN_DLL_DLL_00F5_SIDEKICKBALL_H_

#include "ghidra_import.h"
#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"

typedef struct SidekickBallState {
    u8 unk000[0x25B];
    u8 hittableLatch;
    u8 pad25C[0x26C - 0x25C];
    f32 fadeTimer;
    u8 pad270[4];
    u8 ballMode;
    u8 onPathPoint;
    u8 pad276[0x298 - 0x276];
    f32 unk298;
    u8 pad29C[0x2B0 - 0x29C];
    f32 launchX;
    f32 launchY;
    f32 launchZ;
    u8 pad2BC[0x2C8 - 0x2BC];
    u8 triggerArmed;
    u8 triggerHit;
    u8 sendHoldMessage[2];
} SidekickBallState;

STATIC_ASSERT(offsetof(SidekickBallState, fadeTimer) == 0x26C);
STATIC_ASSERT(offsetof(SidekickBallState, ballMode) == 0x274);
STATIC_ASSERT(offsetof(SidekickBallState, launchX) == 0x2B0);
STATIC_ASSERT(offsetof(SidekickBallState, triggerArmed) == 0x2C8);
STATIC_ASSERT(sizeof(SidekickBallState) == 0x2CC);

extern ObjectDescriptor gSidekickBallObjDescriptor;

int fn_801793A4(GameObject* obj);
void trickyBallFn_801793b8(GameObject* obj, SidekickBallState* state);
void fn_8017962C(GameObject* obj);
int fn_80179650(GameObject* obj);
void fn_80179678(GameObject* obj, GameObject* source);
int SidekickBall_getExtraSize(void);
void SidekickBall_free(int obj);
void SidekickBall_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void SidekickBall_update(GameObject* obj);
void SidekickBall_init(GameObject* obj);
u8 trickyBallMove(GameObject* obj);
void FUN_80179ad4(void);
void FUN_80179afc(int param_1,int param_2,int param_3,int param_4,int param_5,s8 renderState);
void FUN_80179b34(double param_1,double param_2,double param_3,u64 param_4,u64 param_5
                 ,u64 param_6,u64 param_7,u64 param_8,u16 *param_9,
                 u32 param_10,u32 param_11,u32 param_12,u32 param_13,
                 u32 param_14,u32 param_15,u32 param_16);

#endif /* MAIN_DLL_DLL_00F5_SIDEKICKBALL_H_ */
