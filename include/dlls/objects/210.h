#ifndef DLLS_OBJECTS_210_H_
#define DLLS_OBJECTS_210_H_

#include "dlls/object_descriptor.h"
#include "main/dll/curves_collision_state.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"

#define TUMBLEWEED_TYPE_1 0x39d
#define TUMBLEWEED_TYPE_2 0x3fb
#define TUMBLEWEED_TYPE_3 0x4ba
#define TUMBLEWEED_TYPE_4 0x4c1

#define TUMBLEWEED_EFFECT_BURST_SPECIAL  0x34d
#define TUMBLEWEED_EFFECT_BURST_DEFAULT  0x32e
#define TUMBLEWEED_EFFECT_PUFF_SPECIAL   0x34c
#define TUMBLEWEED_EFFECT_PUFF_DEFAULT   0x32d
#define TUMBLEWEED_EFFECT_SPAWN_COUNT    20
#define TUMBLEWEED_PARTFX_MODE_ACTIVE    2
#define TUMBLEWEED_SFX_BURST             0x27d
#define TUMBLEWEED_SFX_HIT_LOOP          0x451
#define TUMBLEWEED_HIT_PULSE_VOLUME_SLOT 0x1f
#define TUMBLEWEED_HIT_PULSE_PERIOD      6
#define TUMBLEWEED_HIT_PULSE_ALT_STYLE   3

#define TUMBLEWEED_EFFECT_FLAG_BURST       0x01
#define TUMBLEWEED_EFFECT_FLAG_PUFF        0x02
#define TUMBLEWEED_EFFECT_FLAG_DESPAWN     0x04
#define TUMBLEWEED_EFFECT_FLAG_IMPACT_SFX  0x08
#define TUMBLEWEED_EFFECT_FLAG_HIT_PULSE   0x10
#define TUMBLEWEED_EFFECT_FLAGS_BURST_PUFF (TUMBLEWEED_EFFECT_FLAG_BURST | TUMBLEWEED_EFFECT_FLAG_PUFF)
#define TUMBLEWEED_EFFECT_FLAGS_ALL                                                                                    \
    (TUMBLEWEED_EFFECT_FLAG_BURST | TUMBLEWEED_EFFECT_FLAG_PUFF | TUMBLEWEED_EFFECT_FLAG_DESPAWN)

#define TUMBLEWEED_PHASE_GROWING         0
#define TUMBLEWEED_PHASE_ARMED           1
#define TUMBLEWEED_PHASE_ROLLING         2
#define TUMBLEWEED_PHASE_PICKUP_APPROACH 3
#define TUMBLEWEED_PHASE_PICKUP_WAIT     4
#define TUMBLEWEED_PHASE_DESPAWNING      5
#define TUMBLEWEED_PHASE_HOMING          6
#define TUMBLEWEED_PHASE_ACTIVE          7

typedef struct TumbleweedPlacement {
    ObjPlacement base; /* 0x00 */
    u8 pad18[3];       /* 0x18 */
    u8 variant;        /* 0x1B */
    f32 scale;         /* 0x1C */
} TumbleweedPlacement;

typedef struct TumbleweedState {
    CurvesCollisionState pathState; /* 0x000 */
    u16 distToTarget;               /* 0x268 */
    u16 triggerRange;               /* 0x26A */
    f32 targetScale;                /* 0x26C */
    union {
        f32 growRate;     /* 0x270 */
        f32 despawnTimer; /* 0x270 */
    };
    u8 pad274[4];          /* 0x274 */
    u8 phase;              /* 0x278 */
    u8 variant;            /* 0x279 */
    u8 flags;              /* 0x27A */
    u8 hitPulseCounter;    /* 0x27B */
    s16 rotVelocityZ;      /* 0x27C */
    s16 rotVelocityY;      /* 0x27E */
    s16 rotVelocityX;      /* 0x280 */
    u8 pad282[2];          /* 0x282 */
    GameObject* targetObj; /* 0x284 */
    f32 anchorPosX;        /* 0x288 */
    f32 anchorPosZ;        /* 0x28C */
    f32* targetPos;        /* 0x290 */
    f32 speed;             /* 0x294 */
    s16 triggerGameBit;    /* 0x298 */
    s16 pickupMsgValue;    /* 0x29A */
    f32 unk29C;            /* 0x29C */
    f32 phaseTimer;        /* 0x2A0 */
} TumbleweedState;

typedef struct TumbleweedInterface {
    ObjectInterface base;
    int (*getPhase)(GameObject* obj);
    void (*setHome)(GameObject* obj, f32 x, f32 z);
    void (*fall)(GameObject* obj);
    void (*gravitateToPoint)(GameObject* obj, f32* targetPos);
    int (*isGravitating)(GameObject* obj);
    void (*setPlayer)(GameObject* obj, GameObject* target);
} TumbleweedInterface;

#define TUMBLEWEED_INTERFACE(tumbleweed) ((TumbleweedInterface*)*((GameObject*)(tumbleweed))->anim.dll)

STATIC_ASSERT(offsetof(TumbleweedPlacement, base) == 0x0);
STATIC_ASSERT(offsetof(TumbleweedPlacement, variant) == 0x1B);
STATIC_ASSERT(offsetof(TumbleweedPlacement, scale) == 0x1C);
STATIC_ASSERT(sizeof(TumbleweedPlacement) == 0x20);

STATIC_ASSERT(offsetof(TumbleweedState, distToTarget) == 0x268);
STATIC_ASSERT(offsetof(TumbleweedState, triggerRange) == 0x26A);
STATIC_ASSERT(offsetof(TumbleweedState, targetScale) == 0x26C);
STATIC_ASSERT(offsetof(TumbleweedState, growRate) == 0x270);
STATIC_ASSERT(offsetof(TumbleweedState, phase) == 0x278);
STATIC_ASSERT(offsetof(TumbleweedState, variant) == 0x279);
STATIC_ASSERT(offsetof(TumbleweedState, flags) == 0x27A);
STATIC_ASSERT(offsetof(TumbleweedState, hitPulseCounter) == 0x27B);
STATIC_ASSERT(offsetof(TumbleweedState, rotVelocityZ) == 0x27C);
STATIC_ASSERT(offsetof(TumbleweedState, rotVelocityY) == 0x27E);
STATIC_ASSERT(offsetof(TumbleweedState, rotVelocityX) == 0x280);
STATIC_ASSERT(offsetof(TumbleweedState, targetObj) == 0x284);
STATIC_ASSERT(offsetof(TumbleweedState, anchorPosX) == 0x288);
STATIC_ASSERT(offsetof(TumbleweedState, anchorPosZ) == 0x28C);
STATIC_ASSERT(offsetof(TumbleweedState, targetPos) == 0x290);
STATIC_ASSERT(offsetof(TumbleweedState, speed) == 0x294);
STATIC_ASSERT(offsetof(TumbleweedState, triggerGameBit) == 0x298);
STATIC_ASSERT(offsetof(TumbleweedState, pickupMsgValue) == 0x29A);
STATIC_ASSERT(offsetof(TumbleweedState, unk29C) == 0x29C);
STATIC_ASSERT(offsetof(TumbleweedState, phaseTimer) == 0x2A0);
STATIC_ASSERT(sizeof(TumbleweedState) == 0x2A4);

STATIC_ASSERT(offsetof(TumbleweedInterface, getPhase) == 0x20);
STATIC_ASSERT(offsetof(TumbleweedInterface, setHome) == 0x24);
STATIC_ASSERT(offsetof(TumbleweedInterface, fall) == 0x28);
STATIC_ASSERT(offsetof(TumbleweedInterface, gravitateToPoint) == 0x2C);
STATIC_ASSERT(offsetof(TumbleweedInterface, isGravitating) == 0x30);
STATIC_ASSERT(offsetof(TumbleweedInterface, setPlayer) == 0x34);
STATIC_ASSERT(sizeof(TumbleweedInterface) == 0x38);

void tumbleweed_updateRollingMotion(GameObject* obj, TumbleweedState* state);
void tumbleweed_setPlayer(GameObject* obj, GameObject* target);
int tumbleweed_isGravitating(GameObject* obj);
void tumbleweed_gravitateToPoint(GameObject* obj, f32* targetPos);
void tumbleweed_fall(GameObject* obj);
void tumbleweed_setHome(GameObject* obj, f32 x, f32 z);
int tumbleweed_getPhase(GameObject* obj);
int tumbleweed_getExtraSize(void);
void tumbleweed_free(GameObject* obj);
void tumbleweed_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible);
void tumbleweed_updateStateMachine(GameObject* obj);
void tumbleweed_updateTargetedStateMachine(GameObject* obj);
void tumbleweed_updateEffects(GameObject* obj);
void tumbleweed_update(GameObject* obj);
void tumbleweed_init(GameObject* obj, TumbleweedPlacement* placement);

extern f32 gTumbleweedCollisionPoint[3];
extern f32 gTumbleweedCollisionPointData[2];
extern ObjectDescriptor16WithPadding gTumbleweedObjDescriptor;

#endif /* DLLS_OBJECTS_210_H_ */
