#ifndef MAIN_DLL_DIM_DLL_0256_DIMSNOWHORN1_H_
#define MAIN_DLL_DIM_DLL_0256_DIMSNOWHORN1_H_

#include "main/game_object.h"
#include "global.h"
#include "ghidra_import.h"
#include "main/dll/baddie_state.h"
#include "main/objanim_update.h"

typedef struct SnowHornEntry
{
    f32 f0;
    f32 f4;
    f32 f8;
    s16 hc;
    u8 padE[2];
    f32 f10;
    f32 f14;
    f32 f18;
    s16 h1c;
    u16 h1e;
    u16 h20;
    u8 pad22[2];
} SnowHornEntry;

STATIC_ASSERT(sizeof(SnowHornEntry) == 0x24);

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

extern f32 lbl_80335128[];
extern int lbl_803E8230;
extern s16 lbl_803DC73C[2];
extern f32 lbl_803DC740[2];
extern s16 lbl_803DC748;
extern f32 lbl_803E8234;
extern f32 lbl_803E8238;
extern f32 lbl_803E823C;
extern f32 lbl_803E8240;
extern f32 lbl_803E8244;
extern f32 lbl_803E8248;
extern f32 lbl_803E824C;
extern f32 lbl_803E8250;
extern f32 lbl_803E8254;
extern f32 lbl_803E8258;
extern f32 lbl_803E825C;
extern f32 lbl_803E8260;
extern f32 lbl_803E8264;
extern f32 lbl_803E8268;
extern f32 lbl_803E826C;
extern f32 lbl_803E8278;
extern f32 lbl_803E827C;
extern f32 lbl_803E8280;
extern f32 lbl_803E8284;
extern f32 lbl_803E8288;
extern f32 lbl_803E828C;
extern f32 lbl_803E8290;
extern f32 lbl_803E8294;
extern f32 lbl_803E8298;
extern f32 lbl_803E829C;
extern f32 lbl_803E82A0;
extern f32 lbl_803E82A4;
extern f32 lbl_803E82A8;
extern f32 lbl_803E82AC;
extern f32 lbl_803E82B0;
extern f32 lbl_803E82B4;
extern f32 gDIMSnowHorn1Gravity;

extern f32 gDIMSnowHorn1ModelMtx[16];
extern f32 gDIMSnowHorn1DefaultStateHandler;
extern int gDIMSnowHorn1StateHandlers[];
extern u8 gDIMSnowHorn1ConfigTable[];
extern void* gDIMSnowHorn1Texture;
extern s16 gDIMSnowHorn1TextureId;
extern int gDIMSnowHorn1PathCollisionData;

void DIMSnowHorn1_func23(void);
int DIMSnowHorn1_defaultStateHandler(void);
int DIMSnowHorn1_stateHandler04(GameObject* obj, int state);
int DIMSnowHorn1_stateHandler00(GameObject* obj);
int DIMSnowHorn1_stateHandler02(GameObject* obj, int state, f32 fv);
int DIMSnowHorn1_stateHandler03(GameObject* obj, int state);
int DIMSnowHorn1_stateHandler01(GameObject* obj, int state, f32 fv);
int DIMSnowHorn1_stateHandler0B(GameObject* obj, int state);
int DIMSnowHorn1_stateHandler09(GameObject* obj, int state, f32 fv);
int DIMSnowHorn1_stateHandler08(GameObject* obj, int state);
int DIMSnowHorn1_stateHandler07(GameObject* obj, int state);
int DIMSnowHorn1_stateHandler06(GameObject* obj, int state);
int DIMSnowHorn1_stateHandler05(GameObject* obj, int state);
int DIMSnowHorn1_stateHandler0A(GameObject* obj, int state, f32 t);
void DIMSnowHorn1_func21(void);
int DIMSnowHorn1_func20(void);
f32 DIMSnowHorn1_func19(GameObject* obj, f32* out);
void DIMSnowHorn1_func18(void* unused, f32* out_f, int* out_i);
void DIMSnowHorn1_setMountMode(GameObject* obj, int value);
int DIMSnowHorn1_func16(void);
void DIMSnowHorn1_func15(s16* packed, f32* outX, f32* outY, f32* outZ);
int DIMSnowHorn1_func14(GameObject* obj);
int DIMSnowHorn1_render2(GameObject* obj);
void DIMSnowHorn1_modelMtxFn(GameObject* obj, f32* out_x, f32* out_y, f32* out_z);
int DIMSnowHorn1_func11(GameObject* obj);
int DIMSnowHorn1_animEventCallback(int obj, int unused, ObjAnimUpdateState* animUpdate);
void DIMSnowHorn1_func22(GameObject* obj, f32 scale);
int DIMSnowHorn1_setScale(GameObject* obj);
int DIMSnowHorn1_getExtraSize(void);
int DIMSnowHorn1_getObjectTypeId(void);
void DIMSnowHorn1_free(int obj);
void DIMSnowHorn1_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void DIMSnowHorn1_hitDetect(void);
void DIMSnowHorn1_update(GameObject* obj);
void DIMSnowHorn1_release(void);
void DIMSnowHorn1_initialise(void);
void DIMSnowHorn1_init(GameObject* obj, int p2, int p3);

#endif /* MAIN_DLL_DIM_DLL_0256_DIMSNOWHORN1_H_ */
