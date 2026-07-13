#ifndef MAIN_DLL_DR_DLL_0258_DRCLOUDRUNNER_H_
#define MAIN_DLL_DR_DLL_0258_DRCLOUDRUNNER_H_

#include "main/game_object.h"
#include "global.h"
#include "main/objanim_update.h"
#include "main/dll/DR/cloudrunner_state.h"

/* placement record passed to init / read by the state handlers */
typedef struct DRCloudRunnerPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 airMeterCapacity; /* 0x1A: initial air meter capacity */
    u8 pad1C[0x1E - 0x1C];
    s16 enableGameBit; /* 0x1E: game bit that enables the mount */
} DRCloudRunnerPlacement;

/* overlay onto CloudRunnerState for the fields it does not yet name */
typedef struct DRCloudRunnerState
{
    u8 pad0[0xAD5 - 0x0];
    u8 flagsAD5;
    u8 padAD6[0xB50 - 0xAD6];
    f32 unkB50;
    u8 padB54[0xBAE - 0xB54];
    s16 unkBAE;
    s16 altMoveEnabled; /* 0xBB0: from placement+0x1a; when set, move 0x203 switches to alternate move 0x20c */
    u8 padBB2[0xBB4 - 0xBB2];
    u8 spawnVariant;
    u8 padBB5[0xBC4 - 0xBB5];
    s8 unkBC4;
    u8 padBC5[0xBC8 - 0xBC5];
} DRCloudRunnerState;

STATIC_ASSERT(offsetof(DRCloudRunnerPlacement, airMeterCapacity) == 0x1A);
STATIC_ASSERT(offsetof(DRCloudRunnerPlacement, enableGameBit) == 0x1E);
STATIC_ASSERT(offsetof(DRCloudRunnerState, flagsAD5) == 0xAD5);
STATIC_ASSERT(offsetof(DRCloudRunnerState, unkB50) == 0xB50);
STATIC_ASSERT(offsetof(DRCloudRunnerState, unkBAE) == 0xBAE);
STATIC_ASSERT(offsetof(DRCloudRunnerState, altMoveEnabled) == 0xBB0);
STATIC_ASSERT(offsetof(DRCloudRunnerState, spawnVariant) == 0xBB4);
STATIC_ASSERT(offsetof(DRCloudRunnerState, unkBC4) == 0xBC4);
STATIC_ASSERT(sizeof(DRCloudRunnerState) == 0xBC8);

typedef struct
{
    f32 x;
    f32 y;
    f32 z;
} Vec3x;

int DR_CloudRunner_defaultStateHandler(void);
void DR_CloudRunner_func21(void);
int DR_CloudRunner_func20(void);
int DR_CloudRunner_func16(void);
int DR_CloudRunner_render2(void);
int DR_CloudRunner_setScale(void);
int DR_CloudRunner_getExtraSize(void);
int DR_CloudRunner_getObjectTypeId(void);
void DR_CloudRunner_release(void);
f32 DR_CloudRunner_func19(int obj, f32* out);
void DR_CloudRunner_func18(int obj, f32* a, int* b);
int DR_CloudRunner_func11(GameObject* obj);
void DR_CloudRunner_setGroundMarkerMatrix(GameObject* obj);
int DR_CloudRunner_func14(GameObject* obj);
void DR_CloudRunner_modelMtxFn(GameObject* obj, f32* x, f32* y, f32* z);
int DR_CloudRunner_stateHandler07(GameObject* obj);
int DR_CloudRunner_stateHandler00(GameObject* obj);
int DR_CloudRunner_stateHandler01(GameObject* obj, int state);
int DR_CloudRunner_stateHandler02(GameObject* obj, int state);
int DR_CloudRunner_stateHandler03(GameObject* obj, int state);
int DR_CloudRunner_stateHandler04(GameObject* obj, int state);
int DR_CloudRunner_stateHandler05(int obj, int state, f32 value);
int DR_CloudRunner_stateHandler06(GameObject* obj, int state);
void DR_CloudRunner_free(GameObject* obj);
void DR_CloudRunner_initialise(void);
void DR_CloudRunner_render(GameObject* p1, int p2, int p3, int p4, int p5, s8 vis);
void DR_CloudRunner_setFlightState(GameObject* obj, int param);
int DR_CloudRunner_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void DR_CloudRunner_func15(int obj, f32* a, f32* b, f32* c);
void DR_CloudRunner_init(GameObject* obj, int p2);
void DR_CloudRunner_func23(GameObject* obj, int mode, int* out);
void DR_CloudRunner_hitDetect(GameObject* obj);
void DR_CloudRunner_update(GameObject* obj);
void fn_802BF0C8(GameObject* obj, CloudRunnerState* state, int mode);

#endif /* MAIN_DLL_DR_DLL_0258_DRCLOUDRUNNER_H_ */
