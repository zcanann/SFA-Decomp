#ifndef MAIN_DLL_DR_DLL_0250_KTREX_H_
#define MAIN_DLL_DR_DLL_0250_KTREX_H_

#include "global.h"
#include "main/game_object.h"
#include "main/model_engine.h"
#include "main/model_light.h"
#include "main/objanim_update.h"
#include "main/shader_api.h"

#define KTREX_LIGHTNING_COUNT 5

typedef struct KtrexMsgBlob
{
    int w[4];
} KtrexMsgBlob;

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
    f32 laneSpeed;
    u8 pad3C[4];
} KtrexPlacement;

typedef struct KtrexState
{
    u8 pad0[0x38];
    f32 unk38;
    u8 pad3C[0x274 - 0x3C];
    s16 scale;
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
    void* rowAX;
    void* rowAY;
    void* rowAZ;
    void* rowBX;
    void* rowBY;
    void* rowBZ;
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
    u8 pathCountdown;
    u32 phaseFlags;
    u8 laneAltSelect;
    u8 pad109[0x23];
    f32 unk12C;
    u8 pad130[0x14];
    f32 unk144;
    u8 pad148[0x24];
    f32 vecX;
    f32 vecY;
    f32 vecZ;
    ModelLightStruct* light;
    void* lightning[KTREX_LIGHTNING_COUNT];
} KTRexArenaState;

typedef struct KTRexRuntime
{
    u8 pad000[0x25f];
    u8 unk25F;
    u8 pad260[0x10];
    s16 unk270;
    u8 pad272[8];
    u8 moveJustStartedA;
    u8 moveJustStartedB;
    u8 pad27C[4];
    f32 localOffsetZ;
    f32 localOffsetX;
    u8 pad288[0xc];
    f32 laneSpeed;
    u8 pad298[8];
    f32 curvePhase;
    u8 pad2A4[0x1c];
    f32 playerDist;
    u8 pad2C4[0xc];
    void* playerObj;
    u8 pad2D4[0x40];
    int handlerState;
    u8 pad318[0x2e];
    u8 moveDone;
    u8 pad347[2];
    u8 unk349;
    u8 pad34A[2];
    s8 unk34C;
    u8 pad34D[2];
    s8 unk34F;
    u8 pad350[4];
    u8 hitCountdown;
    u8 pad355[0x93];
    f32 bobPhase;
    f32 bobRate;
    u8 pad3F0[4];
    s16 unk3F4;
    u8 pad3F6[0x16];
    KTRexArenaState* arena;
} KTRexRuntime;

STATIC_ASSERT(sizeof(KTRexWork) == 0x18);
STATIC_ASSERT(offsetof(KTRexArenaState, light) == 0x178);
STATIC_ASSERT(offsetof(KTRexArenaState, lightning) == 0x17c);
STATIC_ASSERT(offsetof(KTRexRuntime, arena) == 0x40c);

extern KTRexArenaState* gKTRexState;
extern KTRexRuntime* gKTRexRuntime;
extern void* gKTRexStateHandlersA[];
extern void* gKTRexStateHandlersB[];
extern f32 gKTRexLaneSpeedMin[];
extern f32 gKTRexLaneSpeedMax[];
extern f32 gKTRexLaneThreatHalfWidth;
extern MapRomList* gKTRexMapBlock;
extern void* gKTRexResource;
extern KtrexMsgBlob gKTRexMsgTemplate;
extern int gKTRexContactEffectCooldown;
extern KTRexWork gKTRexEffectSpawnWork;

void ktrex_initialiseStateHandlerTables(void);
int ktrex_animEventCallback(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void ktrex_updateAttackEffects(GameObject* obj);
void ktrex_updateContactEffects(GameObject* obj, KTRexRuntime* runtime);
int ktrex_updateArenaPathProgress(KTRexRuntime* runtime);
int ktrex_stateHandlerB01(GameObject* obj, KTRexRuntime* runtime);
int ktrex_stateHandlerB02(GameObject* obj, KTRexRuntime* runtime);
int ktrex_stateHandlerB03(GameObject* obj, KTRexRuntime* runtime);
int ktrex_stateHandlerB04(GameObject* obj, KTRexRuntime* runtime);
int ktrex_stateHandlerB05(GameObject* obj, KTRexRuntime* runtime);
int ktrex_stateHandlerB06(GameObject* obj, KTRexRuntime* runtime);
int ktrex_stateHandlerB07(GameObject* obj, KTRexRuntime* runtime);
int ktrex_stateHandlerB08(GameObject* obj, KTRexRuntime* runtime);
int ktrex_stateHandlerA01(GameObject* obj, KTRexRuntime* runtime);
int ktrex_stateHandlerA02(GameObject* obj, KTRexRuntime* runtime);
int ktrex_stateHandlerA03(GameObject* obj, KTRexRuntime* runtime);
int ktrex_stateHandlerA04(GameObject* obj, KTRexRuntime* runtime);
int ktrex_stateHandlerA05(GameObject* obj, KTRexRuntime* runtime);
int ktrex_stateHandlerA07(GameObject* obj, KTRexRuntime* runtime);
int ktrex_stateHandlerA08(GameObject* obj, KTRexRuntime* runtime);
int ktrex_stateHandlerA09(GameObject* obj, KTRexRuntime* runtime);
int ktrex_stateHandlerA10(GameObject* obj, KTRexRuntime* runtime);
int ktrex_stateHandlerA11(GameObject* obj, KTRexRuntime* runtime);

#endif /* MAIN_DLL_DR_DLL_0250_KTREX_H_ */
