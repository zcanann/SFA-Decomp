#ifndef MAIN_DLL_DLL_0272_HIGHTOP_H_
#define MAIN_DLL_DLL_0272_HIGHTOP_H_

#include "global.h"
#include "main/dll/DR/dr_types.h"
#include "main/dll/baddie_state.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
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
    u8 pad00[0x18];
    s8 rotByte;
    s8 spawnVariant;
    s16 airMeterParam;
    s16 curveScaleParam;
    s16 gameBitId;
} HighTopPlacement;

typedef struct HighTopRuntime
{
    BaddieState baddie;
    u8 pad35C[0x3bc - 0x35c];
    ObjSoundState modelSoundState;
    u8 lookController[0x9fd - 0x3ec];
    u8 flags;
    u8 pad9FE[0xb18 - 0x9fe];
    f32 pathPointWorldPositions[12];
    u8 padB48[0xb6c - 0xb48];
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
    u8 padC34[4];
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

typedef struct HighTopObject
{
    union
    {
        ObjAnimComponent anim;
        struct
        {
            s16 yaw;
            u8 pad02[0xa];
            f32 x;
            f32 y;
            f32 z;
            u8 pad18[0xa0];
        };
    };
    HighTopRuntime* runtime;
} HighTopObject;

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
STATIC_ASSERT(offsetof(HighTopRuntime, flags) == 0x9FD);
STATIC_ASSERT(offsetof(HighTopRuntime, modelSoundState) == 0x3BC);
STATIC_ASSERT(offsetof(HighTopRuntime, turnRateThreshold) == 0xC16);
STATIC_ASSERT(offsetof(HighTopRuntime, substate) == 0xC4B);
STATIC_ASSERT(offsetof(HighTopObject, anim) == 0x00);
STATIC_ASSERT(offsetof(HighTopObject, yaw) == offsetof(ObjAnimComponent, rotX));
STATIC_ASSERT(offsetof(HighTopObject, x) == offsetof(ObjAnimComponent, localPosX));
STATIC_ASSERT(offsetof(HighTopObject, runtime) == 0xB8);

extern void* gHighTopStateHandlers[];
extern void* gHighTopDefaultStateHandler;
extern HtInitData gHighTopLookInitData1;
extern HtInitData gHighTopLookInitData2;
extern int gHighTopAirMeterInitValue;
extern s16 gHighTopMovementSfxIds;
extern f32 gHighTopGroundMarkerMtx[];
extern f32 gHighTopAirMeterSfxInterval;
extern s16 gHighTopBandMoveIds;
extern f32 gHighTopDegToAngle;
extern f32 gHighTopPi;
extern f32 gHighTopBandSpeedThresholds[];
extern int gHighTopIdleSequenceWeights[];
extern int gHighTopIdleSequenceIds[];
extern s16 gHighTopProgressGameBitIds;

int hightop_stateHandler01(GameObject* obj, HighTopRuntime* runtime);
int hightop_stateHandler02(GameObject* obj, HighTopRuntime* runtime, f32 dt);
int hightop_defaultStateHandler(void);
void hightop_func15(void);
int hightop_func14(void);
int hightop_func10(void);
int hightop_func0E(void);
int hightop_func0B(void);
int HighTop_getExtraSize(void);
int HighTop_getObjectTypeId(void);
void HighTop_release(void);
int HighTop_render2(void);
int HighTop_setScale(void);
void hightop_func11(GameObject* obj, int val);
f32 hightop_func13(int obj, f32* out);
void hightop_func12(int obj, f32* a, int* b);
void HighTop_modelMtxFn(int obj, f32* a, f32* b, f32* c);
void HighTop_free(int obj);
int hightop_stateHandler00(GameObject* obj);
int hightop_stateHandler06(GameObject* obj, HighTopRuntime* runtime);
void HighTop_func0F(int obj, f32* ox, f32* oy, f32* oz);
int hightop_stateHandler03(GameObject* obj, HighTopRuntime* runtime);
int hightop_stateHandler05(GameObject* obj, HighTopRuntime* runtime);
int HighTop_seqFn(GameObject* obj);
void hightop_playMovementSfx(GameObject* obj, HighTopRuntime* state2, HighTopRuntime* state);
void HighTop_getLookTargetYaw(GameObject* obj, int mode, int* out);
void HighTop_renderGroundMarker(GameObject* obj, f32 scale);
void HighTop_render(void* obj, int p2, int p3, int p4, int p5, char visible);
void HighTop_init(GameObject* obj, HighTopPlacement* placement);
int hightop_stateHandler08(GameObject* obj, HighTopRuntime* runtime);
void HighTop_initialise(void);
int hightop_handleMotionEvent(int obj, u8 event);
void HighTop_hitDetect(GameObject* obj);
void HighTop_update(GameObject* obj);
int hightop_stateHandler04(int obj, HighTopRuntime* runtime);
int hightop_stateHandler07(GameObject* obj, HighTopRuntime* runtime);
int hightop_stateHandler09(GameObject* obj, HighTopRuntime* runtime);
int hightop_stateHandler10(GameObject* obj, HighTopRuntime* runtime);

extern f32 lbl_803E6AA8;
extern f32 lbl_803E6AB4;
extern f32 lbl_803E6AB8;
extern f32 lbl_803E6ABC;
extern f32 lbl_803E6AC0;
extern f32 lbl_803E6AC4;
extern f32 lbl_803E6AC8;
extern f32 lbl_803E6B34;
extern f32 lbl_803E6B00;
extern f32 lbl_803E6B38;
extern f32 lbl_803E6B3C;
extern int lbl_8032AB48[];
extern int lbl_803E6AA0;
extern int lbl_803DC318;
extern f32 lbl_803E6B4C;
extern f32 lbl_803E6B50;
extern f32 lbl_803E6B54;
extern f32 lbl_803E6B30;
extern s16 gHighTopLookYawOffset;
extern f32 lbl_803E6B40;
extern u8 lbl_803DC308;
extern f32 lbl_803DC324;
extern s16 lbl_803DC314;
extern u8 lbl_8032AAB0[];
extern f32 lbl_803E6B44;
extern f32 lbl_803E6ADC;
extern f32 lbl_803E6B24;
extern f32 lbl_803E6B28;
extern f32 lbl_803E6B2C;
extern f32 lbl_803E6AAC;
extern f32 lbl_803E6AB0;
extern f32 lbl_803E6AD8;
extern f32 lbl_803E6AE0;
extern f32 lbl_803E6AE4;
extern f32 lbl_803E6AE8;
extern f32 lbl_803E6AEC;
extern f32 lbl_803E6AF0;
extern f32 lbl_803E6B04;
extern f32 lbl_803E6B0C;
extern f32 lbl_803E6B10;
extern f32 lbl_803E6B14;
extern f32 lbl_803E6B1C;
extern f32 lbl_803E6B20;
extern f32 lbl_803E6AA4;

#endif /* MAIN_DLL_DLL_0272_HIGHTOP_H_ */
