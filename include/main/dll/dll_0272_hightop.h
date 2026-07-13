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

typedef struct HighTopDeathSpawn
{
    ObjPlacement base;
    u8 pad18[2];
    s16 effectId;
    s16 unk1C;
    s16 gameBit;
    u8 pad20[0xC];
} HighTopDeathSpawn;

typedef struct HightopPlacement
{
    s32 unk0;
    u8 pad4[0x19 - 0x4];
    s8 spawnVariant;
    u8 pad1A[4];
    s16 gameBitId;
} HightopPlacement;

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
STATIC_ASSERT(sizeof(HightopPlacement) == 0x20);
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
int hightop_stateHandler04(int obj, HighTopRuntime* runtime);
int hightop_stateHandler07(GameObject* obj, HighTopRuntime* runtime);
int hightop_stateHandler09(GameObject* obj, HighTopRuntime* runtime);
int hightop_stateHandler10(GameObject* obj, HighTopRuntime* runtime);

#endif /* MAIN_DLL_DLL_0272_HIGHTOP_H_ */
