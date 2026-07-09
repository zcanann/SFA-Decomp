#ifndef MAIN_DLL_DIM_DLL_0256_DIMSNOWHORN1_H_
#define MAIN_DLL_DIM_DLL_0256_DIMSNOWHORN1_H_

#include "global.h"
#include "ghidra_import.h"
#include "main/dll/baddie_state.h"
#include "main/objanim_update.h"

/* Per-object extra state (getExtraSize == 0xD0C); BaddieState is the prefix. */
typedef struct DIMSnowHorn1State
{
    BaddieState baddie;
    u8 lookController[0x96D - 0x35C]; /* dll_2E look-controller block at 0x35C (start evidenced; true extent unknown) */
    u8 unk96D;
    u8 pad96E[0x980 - 0x96E];
    u8 playerNearby; /* 0x980: 1 when player within mount range (mountMode==0); gates spawnPos capture */
    u8 pad981[3];
    f32 spawnPosX;
    f32 spawnPosY;
    f32 spawnPosZ;
    u8 pad990[0x9B0 - 0x990];
    f32 pathPointArray[12]; /* 0x9B0: ObjPath_GetPointWorldPositionArray(2,4) -> 4 XYZ points */
    u8 pad9E0[0x9E8 - 0x9E0];
    f32 pathPosX; /* model-matrix offset vec */
    f32 pathPosY;
    f32 pathPosZ;
    u8 pad9F4[0xA84 - 0x9F4];
    s16 countdownTimer;
    s16 advanceCountThreshold; /* 0xA86: push-count at state+0x334 must reach this (=5) to advance state */
    s16 airMeterValue;
    u8 mountMode; /* 0=unmounted, 2=riding */
    u8 padA8B;
    u8 mode;
    u8 triggerMode;
    u8 flags; /* 0xA8E: bit0x2 riding (GAMEBIT_SNOWHORN_RIDING), bit0x8 hitvol-priority, bit0x20 sequence-triggered */
    u8 queryFlagA8F;   /* 0xA8F: nonzero queried by DIMSnowHorn1_func14 (set cross-DLL) */
    u8 queryFlagA90;   /* 0xA90: nonzero queried by DIMSnowHorn1_func11 (set cross-DLL) */
    u8 proximityPhase; /* 0xA91: 0/1/2 phase toggling linked objects by player distance (stateHandler05) */
    u8 padA92[0xD00 - 0xA92];
    u8 hitReactState; /* 0xD00: ObjHitReact_Update persistent state (in/out), gates fn_8003A168 */
    u8 padD01[0xB];
} DIMSnowHorn1State;

STATIC_ASSERT(sizeof(DIMSnowHorn1State) == 0xD0C);
STATIC_ASSERT(offsetof(DIMSnowHorn1State, countdownTimer) == 0xA84);

void DIMSnowHorn1_func23(void);
int DIMSnowHorn1_defaultStateHandler(void);
int DIMSnowHorn1_stateHandler04(int obj, int state);
int DIMSnowHorn1_stateHandler00(struct GameObject* obj);
int DIMSnowHorn1_stateHandler02(int obj, int state, f32 fv);
int DIMSnowHorn1_stateHandler03(int obj, int state);
int DIMSnowHorn1_stateHandler01(int obj, int state, f32 fv);
int DIMSnowHorn1_stateHandler0B(int obj, int state);
int DIMSnowHorn1_stateHandler09(int obj, int state, f32 fv);
int DIMSnowHorn1_stateHandler08(int obj, int state);
int DIMSnowHorn1_stateHandler07(int obj, int state);
int DIMSnowHorn1_stateHandler06(int obj, int state);
int DIMSnowHorn1_stateHandler05(int obj, int state);
int DIMSnowHorn1_stateHandler0A(int obj, int state, f32 t);
void DIMSnowHorn1_func21(void);
int DIMSnowHorn1_func20(void);
f32 DIMSnowHorn1_func19(struct GameObject* obj, f32* out);
void DIMSnowHorn1_func18(void* unused, f32* out_f, int* out_i);
void DIMSnowHorn1_setMountMode(struct GameObject* obj, int value);
int DIMSnowHorn1_func16(void);
void DIMSnowHorn1_func15(s16* packed, u32 outX, u32 outY, u32 outZ);
int DIMSnowHorn1_func14(struct GameObject* obj);
int DIMSnowHorn1_render2(struct GameObject* obj);
void DIMSnowHorn1_modelMtxFn(struct GameObject* obj, f32* out_x, f32* out_y, f32* out_z);
int DIMSnowHorn1_func11(struct GameObject* obj);
int DIMSnowHorn1_animEventCallback(int obj, int unused, ObjAnimUpdateState* animUpdate);
void DIMSnowHorn1_func22(int obj, f32 scale);
int DIMSnowHorn1_setScale(int obj);
int DIMSnowHorn1_getExtraSize(void);
int DIMSnowHorn1_getObjectTypeId(void);
void DIMSnowHorn1_free(int obj);
void DIMSnowHorn1_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void DIMSnowHorn1_hitDetect(void);
void DIMSnowHorn1_update(int obj);
void DIMSnowHorn1_release(void);
void DIMSnowHorn1_initialise(void);
void DIMSnowHorn1_init(int obj, int p2, int p3);

#endif /* MAIN_DLL_DIM_DLL_0256_DIMSNOWHORN1_H_ */
