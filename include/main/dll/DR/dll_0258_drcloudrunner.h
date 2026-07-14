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

extern void* gDRCloudRunnerStateHandlers[];
extern void* gDRCloudRunnerDefaultStateHandler;
extern s16 gDRCloudRunnerDefaultRotX;
extern s16 gDRCloudRunnerHeadingAngleOffset;
extern s16 gDRCloudRunnerSmoothedRotX;
extern s16 gDRCloudRunnerGameBitIds[4];
extern const int gDRCloudRunnerCurveIds[4];
extern u8 gDRCloudRunnerMoveParamTable[];
extern int gDRCloudRunnerAirMeterBaseline;
extern const Vec3x gDRCloudRunnerVecTable[];
extern s16 gDRCloudRunnerRollAngleLimits;

extern int lbl_803E83A0;
extern f32 lbl_803E83A4;
extern f32 lbl_803E83A8;
extern f32 lbl_803E83AC;
extern f32 lbl_803E83B0;
extern f32 lbl_803E83B4;
extern f32 lbl_803E83B8;
extern f32 lbl_803E83BC;
extern f32 lbl_803E83C0;
extern f32 lbl_803E83C4;
extern f32 lbl_803E83C8;
extern f32 lbl_803E83CC;
extern f32 lbl_803E83D0;
extern f32 lbl_803E83D4;
extern f32 lbl_803E83D8;
extern f32 lbl_803E83DC;
extern f32 lbl_803E83E0;
extern f32 lbl_803E83E4;
extern f32 lbl_803E83E8;
extern f32 lbl_803E83EC;
extern f32 lbl_803E83F0;
extern f32 lbl_803E83F4;
extern f32 lbl_803E83F8;
extern f32 lbl_803E83FC;
extern f32 lbl_803E8408;
extern f32 lbl_803E840C;
extern f32 lbl_803E8410;
extern f32 lbl_803E8414;
extern f32 lbl_803E8418;
extern f32 lbl_803E841C;
extern f32 lbl_803E8420;
extern f32 lbl_803E8424;
extern char sOnCloudFormat[];

extern int lbl_803DC770;
extern int lbl_803DC774;
extern int lbl_803DC778;
extern int lbl_803DC77C;
extern int lbl_803DC780;
extern int lbl_803DC784;
extern f32 lbl_803DC78C;
extern f32 lbl_803DC790;

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
void fn_802BF4D8(GameObject* obj);

#endif /* MAIN_DLL_DR_DLL_0258_DRCLOUDRUNNER_H_ */
