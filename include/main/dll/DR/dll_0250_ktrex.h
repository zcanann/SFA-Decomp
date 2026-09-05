#ifndef MAIN_DLL_DR_DLL_0250_KTREX_H_
#define MAIN_DLL_DR_DLL_0250_KTREX_H_

#include "global.h"
#include "main/dll/dll_005A_staffcollision.h"
#include "game/objects/object.h"
#include "main/dll/baddie_state.h"
#include "main/model_engine.h"
#include "main/model_light.h"
#include "main/objseq.h"
#include "main/shader_api.h"

#define KTREX_LIGHTNING_COUNT 5

typedef struct KtrexMsgBlob
{
    int w[4];
} KtrexMsgBlob;

STATIC_ASSERT(sizeof(KtrexMsgBlob) == 0x10);

typedef struct KTRexWork
{
    s16 unk0;
    s16 unk2;
    s16 unk4;
    u8 pad6[0x8 - 0x6];
    f32 unk8;
    f32 posX;
    f32 posY;
    f32 posZ;
} KTRexWork;

typedef struct KtrexPlacement
{
    u8 pad0[0x38];
    f32 laneSpeeds[3];
} KtrexPlacement;

typedef struct KtrexState
{
    u8 pad0[0x38];
    f32 unk38;
    u8 pad3C[0x274 - 0x3C];
    s16 controlMode;
    u8 pad276[0x5A4 - 0x276];
} KtrexState;

typedef struct KTRexArenaState
{
    RingBufferQueue* stack;
    f32 stateTimer;
    f32 laneLerpT;
    int lastPhase;
    f32 laneAX[4];
    f32 laneAY[4];
    f32 laneAZ[4];
    f32 laneBX[4];
    f32 laneBY[4];
    f32 laneBZ[4];
    f32 laneCX[4];
    f32 laneCY[4];
    f32 laneCZ[4];
    f32 laneDX[4];
    f32 laneDY[4];
    f32 laneDZ[4];
    f32* rowAX;
    f32* rowAY;
    f32* rowAZ;
    f32* rowBX;
    f32* rowBY;
    f32* rowBZ;
    f32 posX;
    f32 posY;
    f32 posZ;
    f32 laneFrac;
    s16 homeYaw;
    u16 timerFA;
    u8 laneIndex;
    u8 moveVariant;
    u8 currentLaneMask;
    u8 activeLaneMask;
    u8 laneMode;
    u8 phaseCounter;
    u8 phaseCountdown;
    s8 pathCountdown;
    u32 phaseFlags;
    u8 laneAltSelect;
    u8 pad109[0x10C - 0x109];
    KTRexWork spawnWork[4];
    f32 vecX;
    f32 vecY;
    f32 vecZ;
    ModelLightStruct* light;
    void* lightning[KTREX_LIGHTNING_COUNT];
    f32 breathSfxTimer;
} KTRexArenaState;

typedef struct KTRexLaneTuning
{
    f32 speedMax[3];
    int curveIds[4][4];
} KTRexLaneTuning;



STATIC_ASSERT(sizeof(KTRexWork) == 0x18);
STATIC_ASSERT(offsetof(KTRexArenaState, spawnWork) == 0x10c);
STATIC_ASSERT(offsetof(KTRexArenaState, light) == 0x178);
STATIC_ASSERT(offsetof(KTRexArenaState, lightning) == 0x17c);
STATIC_ASSERT(offsetof(KTRexArenaState, breathSfxTimer) == 0x190);
STATIC_ASSERT(sizeof(KTRexLaneTuning) == 0x4c);
STATIC_ASSERT(offsetof(KTRexLaneTuning, curveIds) == 0xc);

extern KTRexArenaState* gKTRexState;
extern GroundBaddieState* gKTRexRuntime;
extern void* gKTRexStateHandlersA[];
extern void* gKTRexStateHandlersB[];
extern f32 gKTRexLaneSpeedMin[];
extern KTRexLaneTuning gKTRexLaneTuning;
extern MapRomList* gKTRexMapBlock;
extern StaffCollisionInterface** gKTRexResource;
extern const KtrexMsgBlob gKTRexMsgTemplate;
extern int gKTRexContactEffectCooldown;
extern KTRexWork gKTRexEffectSpawnWork;
extern s16 gKTRexLaneEnabledGameBits[4];
extern s16 gKTRexLaneModeGameBits[4];
extern s16 gKTRexMoveIdByLaneB05[4];
extern s16 gKTRexMoveIdByVariantB04[4];
extern u16 gKTRexPhaseFlagsByVariantB04[4];
extern s16 gKTRexWalkMoveIdByLane[4];
extern u16 gKTRexWalkPhaseFlagsByLaneEvent4[4];
extern u16 gKTRexWalkPhaseFlagsByLaneEvent2[4];
extern u16 gKTRexWalkEndPhaseFlagsByLaneAlt[4];
extern u16 gKTRexWalkEndPhaseFlagsByLane[4];
extern f32 gKTRexCurvePhaseByVariantB04[];
extern s16 gKTRexTurnMoveIdByLaneAndDir[];
extern f32 gKTRexTurnCurvePhaseByLane[];

void ktrex_initialiseStateHandlerTables(void);
int ktrex_animEventCallback(GameObject* obj, int unused, ObjSeqState* animUpdate);
void ktrex_updateAttackEffects(GameObject* obj);
void ktrex_updateContactEffects(GameObject* obj, GroundBaddieState* runtime);
int ktrex_updateArenaPathProgress(GroundBaddieState* runtime);
int ktrex_stateHandlerB01(GameObject* obj, GroundBaddieState* runtime);
int ktrex_stateHandlerB02(GameObject* obj, GroundBaddieState* runtime);
int ktrex_stateHandlerB03(GameObject* obj, GroundBaddieState* runtime);
int ktrex_stateHandlerB04(GameObject* obj, GroundBaddieState* runtime);
int ktrex_stateHandlerB05(GameObject* obj, GroundBaddieState* runtime);
int ktrex_stateHandlerB06(GameObject* obj, GroundBaddieState* runtime);
int ktrex_stateHandlerB07(GameObject* obj, GroundBaddieState* runtime);
int ktrex_stateHandlerB08(GameObject* obj, GroundBaddieState* runtime);
int ktrex_stateHandlerA01(GameObject* obj, GroundBaddieState* runtime);
int ktrex_stateHandlerA02(GameObject* obj, GroundBaddieState* runtime);
int ktrex_stateHandlerA03(GameObject* obj, GroundBaddieState* runtime);
int ktrex_stateHandlerA04(GameObject* obj, GroundBaddieState* runtime);
int ktrex_stateHandlerA05(GameObject* obj, GroundBaddieState* runtime);
int ktrex_stateHandlerA07(GameObject* obj, GroundBaddieState* runtime);
int ktrex_stateHandlerA08(GameObject* obj, GroundBaddieState* runtime);
int ktrex_stateHandlerA09(GameObject* obj, GroundBaddieState* runtime);
int ktrex_stateHandlerA10(GameObject* obj, GroundBaddieState* runtime);
int ktrex_stateHandlerA11(GameObject* obj, GroundBaddieState* runtime);

#endif /* MAIN_DLL_DR_DLL_0250_KTREX_H_ */
