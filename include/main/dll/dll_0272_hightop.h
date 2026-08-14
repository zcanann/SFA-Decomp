#ifndef MAIN_DLL_DLL_0272_HIGHTOP_H_
#define MAIN_DLL_DLL_0272_HIGHTOP_H_

#include "main/objprint_character_api.h"
#include "global.h"
#include "main/dll/DR/dr_types.h"
#include "main/dll/baddie_state.h"
#include "main/dll/dll_002E_moveLib.h"
#include "main/dll/curve_walker.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "main/objprint_sound_api.h"

typedef struct HtInitData
{
    s16 v[9];
} HtInitData;

STATIC_ASSERT(sizeof(HtInitData) == 0x12);

typedef struct HighTopDeathSpawn
{
    ObjPlacement base;
    u8 pad18[2];
    s16 effectId;
    s16 unk1C;
    s16 gameBit;
    u8 pad20[0xC];
} HighTopDeathSpawn;

typedef struct HighTopPlacement
{
    ObjPlacement base;
    s8 rotByte;
    s8 spawnVariant;
    s16 airMeterParam;
    s16 curveScaleParam;
    s16 gameBitId;
} HighTopPlacement;

typedef struct HighTopRuntime
{
    BaddieState baddie;
    u8 pad35C[0x38c - 0x35c];
    CharacterEyeAnimState eyeAnimState; /* 0x38c: head-aim / eye-blink record (characterDoEyeAnims) */
    u8 pad3B4[0x3bc - 0x3b4];
    ObjSoundState modelSoundState;
    MoveLibState lookController; /* 0x3ec: dll_2E look-controller block */
    RomCurveWalker curveWalker;
    f32 pathPointWorldPositions[12];
    ObjKfAnimState keyframeAnimState;
    u8 padB60[0xb6c - 0xb60];
    f32 pathPoint2X;
    f32 pathPoint2Y;
    f32 pathPoint2Z;
    f32 pathPoint0X;
    f32 pathPoint0Y;
    f32 pathPoint0Z;
    u8 padB84[0xc16 - 0xb84];
    s16 turnRateThreshold;
    s16 airMeterRemaining;
    u8 padC1A[2];
    f32 lookTargetX;
    f32 lookTargetY;
    f32 lookTargetZ;
    f32 curveFollowSpeedScale;
    f32 transitionTimer;
    f32 stateTimer;
    f32 randomTimerC34;
    f32 sfxIntervalTimer;
    s32 savedControlMode;
    u16 flagsC40;
    u8 idleSeqIndex;
    u8 unkC43;
    u8 padC44;
    u8 unkC45;
    u8 padC46[3];
    BitFlags8 flagsC49;
    BitFlags8 flagsC4A;
    u8 substate;
} HighTopRuntime;

STATIC_ASSERT(offsetof(HighTopDeathSpawn, effectId) == 0x1A);
STATIC_ASSERT(offsetof(HighTopDeathSpawn, gameBit) == 0x1E);
STATIC_ASSERT(sizeof(HighTopDeathSpawn) == 0x2C);
STATIC_ASSERT(offsetof(HighTopPlacement, rotByte) == 0x18);
STATIC_ASSERT(offsetof(HighTopPlacement, spawnVariant) == 0x19);
STATIC_ASSERT(offsetof(HighTopPlacement, airMeterParam) == 0x1A);
STATIC_ASSERT(offsetof(HighTopPlacement, curveScaleParam) == 0x1C);
STATIC_ASSERT(offsetof(HighTopPlacement, gameBitId) == 0x1E);
STATIC_ASSERT(sizeof(HighTopPlacement) == 0x20);
STATIC_ASSERT(sizeof(HighTopRuntime) == 0xC4C);
STATIC_ASSERT(offsetof(HighTopRuntime, lookController) == 0x3EC);
STATIC_ASSERT(offsetof(HighTopRuntime, lookController.modeBits) == 0x9FD);
STATIC_ASSERT(offsetof(HighTopRuntime, modelSoundState) == 0x3BC);
STATIC_ASSERT(offsetof(HighTopRuntime, keyframeAnimState) == 0xB48);
STATIC_ASSERT(offsetof(HighTopRuntime, turnRateThreshold) == 0xC16);
STATIC_ASSERT(offsetof(HighTopRuntime, substate) == 0xC4B);

extern void* gHighTopStateHandlers[];
extern void* gHighTopDefaultStateHandler;
extern const HtInitData gHighTopLookInitData1;
extern const HtInitData gHighTopLookInitData2;
extern int gHighTopAirMeterInitValue;
extern s16 gHighTopMovementSfxIds[2];
extern f32 gHighTopModelMtx[];
extern s16 gHighTopBandMoveIds[2];
extern f32 gHighTopBandSpeedThresholds[];
extern int gHighTopIdleSequenceWeights[];
extern int gHighTopIdleSequenceIds[];
extern s16 gHighTopProgressGameBitIds[4];

int hightop_stateHandler01(GameObject* obj, HighTopRuntime* runtime);
int hightop_stateHandler02(GameObject* obj, HighTopRuntime* runtime, f32 dt);
int hightop_defaultStateHandler(void);
void hightop_func15(void);
int HighTop_getRacePosition(void);
int HighTop_getMountState(void);
int HighTop_getDismountSide(void);
int HighTop_getMountSide(void);
int HighTop_getExtraSize(void);
int HighTop_getObjectTypeId(void);
void HighTop_release(void);
int HighTop_canDismount(void);
int HighTop_canMount(void);
void HighTop_setMountState(GameObject* obj, int val);
f32 hightop_func13(int obj, f32* out);
void HighTop_getPlayerAnim(int obj, f32* a, int* b);
void HighTop_getRiderPosition(GameObject* obj, f32* a, f32* b, f32* c);
void HighTop_free(GameObject* obj);
int hightop_stateHandler00(GameObject* obj);
int hightop_stateHandler06(GameObject* obj, HighTopRuntime* runtime);
void HighTop_getCameraPosition(int obj, f32* ox, f32* oy, f32* oz);
int hightop_stateHandler03(GameObject* obj, HighTopRuntime* runtime);
int hightop_stateHandler05(GameObject* obj, HighTopRuntime* runtime);
int HighTop_seqFn(GameObject* obj);
void hightop_playMovementSfx(GameObject* obj, HighTopRuntime* state2, HighTopRuntime* state);
void HighTop_getLookTargetYaw(GameObject* obj, int mode, int* out);
void HighTop_handleRiderScale(GameObject* obj, f32 scale);
void HighTop_render(void* obj, int p2, int p3, int p4, int p5, char visible);
void HighTop_init(GameObject* obj, HighTopPlacement* placement);
int hightop_stateHandler08(GameObject* obj, HighTopRuntime* runtime);
void HighTop_initialise(void);
int hightop_handleMotionEvent(GameObject* obj, u8 event);
void HighTop_hitDetect(GameObject* obj);
void HighTop_update(GameObject* obj);
int hightop_stateHandler04(GameObject* obj, HighTopRuntime* runtime);
int hightop_stateHandler07(GameObject* obj, HighTopRuntime* runtime);
int hightop_stateHandler09(GameObject* obj, HighTopRuntime* runtime);
int hightop_stateHandler10(GameObject* obj, HighTopRuntime* runtime);

typedef struct HighTopTuning
{
    int shacklePathPoints[4];
    f32 unk10[22];
} HighTopTuning;

STATIC_ASSERT(sizeof(HighTopTuning) == 0x68);
STATIC_ASSERT(offsetof(HighTopTuning, unk10) == 0x10);

extern HighTopTuning gHighTopTuning;
extern f32 gHighTopPathPointRadii[2];
extern s16 gHighTopLookYawOffset;
extern u8 gHighTopAmbientSoundDef[8];
extern f32 gHighTopCurveFollowSpeedFactor;
extern s16 lbl_803DC314[2];
extern u8 gHighTopConfigTable[];

#endif /* MAIN_DLL_DLL_0272_HIGHTOP_H_ */
