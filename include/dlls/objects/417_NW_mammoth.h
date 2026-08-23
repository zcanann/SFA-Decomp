#ifndef DLLS_OBJECTS_417_NW_MAMMOTH_H_
#define DLLS_OBJECTS_417_NW_MAMMOTH_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "main/curve_types.h"
#include "main/dll/curves_collision_state.h"
#include "main/objseq.h"
#include "main/objprint_character_api.h"

#define NW_MAMMOTH_PLACEMENT_SIZE   0x24
#define NW_MAMMOTH_PATH_POINT_COUNT 4

typedef enum NwMammothBehaviorMode {
    NW_MAMMOTH_BEHAVIOR_FEED_QUEST = 0,
    NW_MAMMOTH_BEHAVIOR_MODE1_PATROL = 1,
    NW_MAMMOTH_BEHAVIOR_ARTIFACT_QUEST = 2,
    NW_MAMMOTH_BEHAVIOR_PATROL = 3,
    NW_MAMMOTH_BEHAVIOR_GATEKEEPER = 4,
} NwMammothBehaviorMode;

typedef enum NwMammothStateIndex {
    NW_MAMMOTH_STATE_FEED_INTRO = 0,
    NW_MAMMOTH_STATE_FEED_FIRST_ROOT = 1,
    NW_MAMMOTH_STATE_FEED_SECOND_ROOT = 2,
    NW_MAMMOTH_STATE_FEED_SATISFIED = 3,
    NW_MAMMOTH_STATE_ARTIFACT_PROMPT = 4,
    NW_MAMMOTH_STATE_ARTIFACT_COLLECTED = 5,
    NW_MAMMOTH_STATE_ARTIFACT_COMPLETE = 6,
    NW_MAMMOTH_STATE_PATROL_PAUSED = 7,
    NW_MAMMOTH_STATE_PATROL_MOVING = 8,
    NW_MAMMOTH_STATE_GATEKEEPER_IDLE = 9,
    NW_MAMMOTH_STATE_GATEKEEPER_ALERT = 10,
    NW_MAMMOTH_STATE_GATEKEEPER_PROMPT = 11,
    NW_MAMMOTH_STATE_GATEKEEPER_RESUME_RESCUE = 12,
    NW_MAMMOTH_STATE_GATEKEEPER_COLLECTING = 13,
    NW_MAMMOTH_STATE_GATEKEEPER_HOMING_TUMBLEWEED = 14,
    NW_MAMMOTH_STATE_GATEKEEPER_BREAK_TUMBLEWEED = 15,
    NW_MAMMOTH_STATE_GATEKEEPER_RESCUED_SEQUENCE = 16,
    NW_MAMMOTH_STATE_GATEKEEPER_RESCUE_COMPLETE = 17,
    NW_MAMMOTH_STATE_GATEKEEPER_TRANSITION = 18,
    NW_MAMMOTH_STATE_GATEKEEPER_POST_RESCUE = 19,
    NW_MAMMOTH_STATE_SLEEP_START = 20,
    NW_MAMMOTH_STATE_SLEEPING = 21,
    NW_MAMMOTH_STATE_WAKE_UP = 22,
    NW_MAMMOTH_STATE_COUNT = 24,
} NwMammothStateIndex;

typedef struct NwMammothPlacement {
    ObjPlacement base;
    s16 triggerDistance;
    u8 unknown1A[2];
    s8 modelIndex;
    s8 behaviorMode; /* NwMammothBehaviorMode */
    u8 unknown1E[NW_MAMMOTH_PLACEMENT_SIZE - 0x1E];
} NwMammothPlacement;

typedef struct NwMammothCurveState {
    Curve curve;
    u8 unknown9C[0x110 - sizeof(Curve)];
} NwMammothCurveState;

typedef struct NwMammothState {
    f32 sfxTimer;
    f32 stateTimer;
    f32 airMeterValue;
    f32 spawnPosX;
    f32 spawnPosY;
    f32 spawnPosZ;
    f32 playerDistanceSq;
    f32 partfxTimer;
    u8 unknown20[0x24 - 0x20];
    GameObject* trackedObject;
    GameObject* playerObject;
    u8 unknown2C[0x48 - 0x2C];
    u8* triggerList;
    f32 animStepScale;
    f32 hitReactStepScale;
    f32 pathSpeed;
    u8 unknown58[0x5C - 0x58];
    NwMammothCurveState curveState;
    CurvesCollisionState pathState;
    u8 hitReactState;
    u8 unknown3D5[0x408 - 0x3D5];
    u8 stateIndex;        /* NwMammothStateIndex */
    u8 daytimeStateIndex; /* NwMammothStateIndex saved before the sleep cycle */
    u8 unknown40A[2];
    CharacterEyeAnimState eyeAnim;
    u8 unknown434[0x43C - 0x434];
    u8 runtimeFlags;
    u8 unknown43D[0x43F - 0x43D];
    s8 uiMessageCount;
    ObjAnimEventList animEvents;
    Vec3f pathPoints[NW_MAMMOTH_PATH_POINT_COUNT];
} NwMammothState;

STATIC_ASSERT(sizeof(NwMammothPlacement) == NW_MAMMOTH_PLACEMENT_SIZE);
STATIC_ASSERT(offsetof(NwMammothPlacement, triggerDistance) == 0x18);
STATIC_ASSERT(offsetof(NwMammothPlacement, modelIndex) == 0x1C);
STATIC_ASSERT(offsetof(NwMammothPlacement, behaviorMode) == 0x1D);

STATIC_ASSERT(sizeof(NwMammothCurveState) == 0x110);
STATIC_ASSERT(offsetof(NwMammothCurveState, curve.sample) == 0x68);

STATIC_ASSERT(sizeof(NwMammothState) == 0x48C);
STATIC_ASSERT(offsetof(NwMammothState, spawnPosX) == 0x0C);
STATIC_ASSERT(offsetof(NwMammothState, playerDistanceSq) == 0x18);
STATIC_ASSERT(offsetof(NwMammothState, partfxTimer) == 0x1C);
STATIC_ASSERT(offsetof(NwMammothState, trackedObject) == 0x24);
STATIC_ASSERT(offsetof(NwMammothState, playerObject) == 0x28);
STATIC_ASSERT(offsetof(NwMammothState, triggerList) == 0x48);
STATIC_ASSERT(offsetof(NwMammothState, animStepScale) == 0x4C);
STATIC_ASSERT(offsetof(NwMammothState, hitReactStepScale) == 0x50);
STATIC_ASSERT(offsetof(NwMammothState, pathSpeed) == 0x54);
STATIC_ASSERT(offsetof(NwMammothState, curveState) == 0x5C);
STATIC_ASSERT(offsetof(NwMammothState, pathState) == 0x16C);
STATIC_ASSERT(offsetof(NwMammothState, hitReactState) == 0x3D4);
STATIC_ASSERT(offsetof(NwMammothState, stateIndex) == 0x408);
STATIC_ASSERT(offsetof(NwMammothState, daytimeStateIndex) == 0x409);
STATIC_ASSERT(offsetof(NwMammothState, eyeAnim) == 0x40C);
STATIC_ASSERT(offsetof(NwMammothState, runtimeFlags) == 0x43C);
STATIC_ASSERT(offsetof(NwMammothState, uiMessageCount) == 0x43F);
STATIC_ASSERT(offsetof(NwMammothState, animEvents) == 0x440);
STATIC_ASSERT(offsetof(NwMammothState, pathPoints) == 0x45C);

f32* NW_mammoth_getSpawnPosition(GameObject* obj);
int NW_mammoth_processAnimEvents(GameObject* obj, int unusedArg, ObjSeqState* animUpdate);
void NW_mammoth_updateEyeTracking(GameObject* obj, NwMammothState* state, int enabled);
int NW_mammoth_getExtraSize(void);
void NW_mammoth_free(GameObject* obj);
void NW_mammoth_render(GameObject* obj, u32 p2, u32 p3, u32 p4, u32 p5, char unusedVisible);
void NW_mammoth_update(GameObject* obj, int unusedArg);
void NW_mammoth_init(GameObject* obj, NwMammothPlacement* placement, int isReload);

extern ObjectDescriptor gNW_mammothObjDescriptor;

#endif /* DLLS_OBJECTS_417_NW_MAMMOTH_H_ */
