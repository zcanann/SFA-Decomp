#ifndef DLLS_OBJECTS_332_H_
#define DLLS_OBJECTS_332_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "main/objprint_character_api.h"
#include "game/objects/object_setup.h"
#include "main/dll/curve_walker.h"
#include "main/objseq.h"
#include "main/objprint_sound_api.h"
#include "main/vec_types.h"

typedef enum BabyCloudRunnerStateId {
    BABYCLOUDRUNNER_STATE_FIND_CURVE = 0,
    BABYCLOUDRUNNER_STATE_FOLLOW_CURVE = 1,
    BABYCLOUDRUNNER_STATE_CHASED = 2,
    BABYCLOUDRUNNER_STATE_FREED = 3,
} BabyCloudRunnerStateId;

typedef enum BabyCloudRunnerCaptureFlag {
    BABYCLOUDRUNNER_CAPTURE_ACTIVE = 0x01,
} BabyCloudRunnerCaptureFlag;

typedef struct BabyCloudRunnerPlacement {
    ObjPlacement base;
    s16 outerRadius;
    s16 innerRadius;
    u8 initialBehaviourState;
    u8 initialYaw;
    s16 enableGameBit;
    u8 pad20[0x02];
    s16 runnerGameBit;
} BabyCloudRunnerPlacement;

typedef struct BabyCloudRunnerStateFlags {
    u8 atRoost : 1;
    u8 burrowSfxLatched : 1;
    u8 unused : 6;
} BabyCloudRunnerStateFlags;

typedef struct BabyCloudRunnerState {
    f32 captureTimer;
    u8 pad004[0x14];
    Vec3f handoffPosition;
    u8 pad024[0x18];
    CharacterEyeAnimState eyeAnimState;
    u8 pad64[0x8];
    ObjSoundState soundState;
    u8 pad09C[0x0C];
    f32 animSpeed;
    f32 scale;
    int unknown0B0;
    int unknown0B4;
    int unknown0B8;
    int unknown0BC;
    int turnLatch;
    int behaviourState;
    u8 pad0C8[0x04];
    int unknown0CC;
    s16 roostYaw;
    u8 pad0D2[0x42];
    GameObject* linkedObject;
    u8 pad118[0x0C];
    RomCurveWalker curveWalker;
    u8 captureFlags;
    u8 pad22D[0x03];
    int runnerState;
    int runnerIndex;
    f32 countdownTimer;
    f32 curveSpeed;
    s16* mutterSfxTable;
    BabyCloudRunnerStateFlags stateFlags;
    u8 pad245[0x03];
} BabyCloudRunnerState;

STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, base) == 0x00);
STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, outerRadius) == 0x18);
STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, innerRadius) == 0x1A);
STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, initialBehaviourState) == 0x1C);
STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, initialYaw) == 0x1D);
STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, enableGameBit) == 0x1E);
STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, pad20) == 0x20);
STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, runnerGameBit) == 0x22);

STATIC_ASSERT(sizeof(BabyCloudRunnerStateFlags) == 0x01);

STATIC_ASSERT(offsetof(BabyCloudRunnerState, captureTimer) == 0x000);
STATIC_ASSERT(offsetof(BabyCloudRunnerState, handoffPosition) == 0x018);
STATIC_ASSERT(offsetof(BabyCloudRunnerState, eyeAnimState) == 0x03C);
STATIC_ASSERT(offsetof(BabyCloudRunnerState, soundState) == 0x06C);
STATIC_ASSERT(offsetof(BabyCloudRunnerState, animSpeed) == 0x0A8);
STATIC_ASSERT(offsetof(BabyCloudRunnerState, scale) == 0x0AC);
STATIC_ASSERT(offsetof(BabyCloudRunnerState, unknown0B0) == 0x0B0);
STATIC_ASSERT(offsetof(BabyCloudRunnerState, unknown0B4) == 0x0B4);
STATIC_ASSERT(offsetof(BabyCloudRunnerState, unknown0B8) == 0x0B8);
STATIC_ASSERT(offsetof(BabyCloudRunnerState, unknown0BC) == 0x0BC);
STATIC_ASSERT(offsetof(BabyCloudRunnerState, turnLatch) == 0x0C0);
STATIC_ASSERT(offsetof(BabyCloudRunnerState, behaviourState) == 0x0C4);
STATIC_ASSERT(offsetof(BabyCloudRunnerState, pad0C8) == 0x0C8);
STATIC_ASSERT(offsetof(BabyCloudRunnerState, unknown0CC) == 0x0CC);
STATIC_ASSERT(offsetof(BabyCloudRunnerState, roostYaw) == 0x0D0);
STATIC_ASSERT(offsetof(BabyCloudRunnerState, pad0D2) == 0x0D2);
STATIC_ASSERT(offsetof(BabyCloudRunnerState, linkedObject) == 0x114);
STATIC_ASSERT(offsetof(BabyCloudRunnerState, pad118) == 0x118);
STATIC_ASSERT(offsetof(BabyCloudRunnerState, curveWalker) == 0x124);
STATIC_ASSERT(offsetof(BabyCloudRunnerState, captureFlags) == 0x22C);
STATIC_ASSERT(offsetof(BabyCloudRunnerState, pad22D) == 0x22D);
STATIC_ASSERT(offsetof(BabyCloudRunnerState, runnerState) == 0x230);
STATIC_ASSERT(offsetof(BabyCloudRunnerState, runnerIndex) == 0x234);
STATIC_ASSERT(offsetof(BabyCloudRunnerState, countdownTimer) == 0x238);
STATIC_ASSERT(offsetof(BabyCloudRunnerState, curveSpeed) == 0x23C);
STATIC_ASSERT(offsetof(BabyCloudRunnerState, mutterSfxTable) == 0x240);
STATIC_ASSERT(offsetof(BabyCloudRunnerState, stateFlags) == 0x244);
STATIC_ASSERT(offsetof(BabyCloudRunnerState, pad245) == 0x245);
STATIC_ASSERT(sizeof(BabyCloudRunnerState) == 0x248);

int babyCloudRunner_updateBurrowAnimation(GameObject* obj);
void babyCloudRunner_turnTowardTarget(GameObject* obj, GameObject* target, BabyCloudRunnerState* state, int playMove);
/* gBabyCloudRunnerObjDescriptor from slot02 onwards: the export table other
   objects reach through obj->anim.dll. */
typedef struct BabyCloudRunnerInterface {
    void* pad00[8];
    int (*func0A)(GameObject* object);
    int (*tryCapture)(GameObject* object);
} BabyCloudRunnerInterface;

#define BABY_CLOUD_RUNNER_INTERFACE(baby) ((BabyCloudRunnerInterface*)*((GameObject*)(baby))->anim.dll)

STATIC_ASSERT(offsetof(BabyCloudRunnerInterface, func0A) == 0x20);
STATIC_ASSERT(offsetof(BabyCloudRunnerInterface, tryCapture) == 0x24);

int babyCloudRunner_tryCapture(GameObject* object);
int babyCloudRunner_func0A(GameObject* obj);
int babyCloudRunner_sequenceCallback(GameObject* obj, int unused, ObjSeqState* animUpdate);
int babyCloudRunner_getExtraSize(void);
int babyCloudRunner_getObjectTypeId(void);
void babyCloudRunner_free(GameObject* obj);
void babyCloudRunner_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                            s8 visible);
void babyCloudRunner_hitDetect(void);
void babyCloudRunner_update(GameObject* obj);
void babyCloudRunner_init(GameObject* obj, BabyCloudRunnerPlacement* placement);
void babyCloudRunner_release(void);
void babyCloudRunner_initialise(void);

extern ObjectDescriptor12 gBabyCloudRunnerObjDescriptor;

#endif /* DLLS_OBJECTS_332_H_ */
