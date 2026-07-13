#ifndef MAIN_DLL_DLL_00D2_TUMBLEWEED_H_
#define MAIN_DLL_DLL_00D2_TUMBLEWEED_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "types.h"
#include "global.h"

#define TUMBLEWEED_TYPE_1 0x39d
#define TUMBLEWEED_TYPE_3 0x4ba
#define TUMBLEWEED_TYPE_4 0x4c1

#define TUMBLEWEED_EFFECT_BURST_SPECIAL  0x34d
#define TUMBLEWEED_EFFECT_BURST_DEFAULT  0x32e
#define TUMBLEWEED_EFFECT_PUFF_SPECIAL   0x34c
#define TUMBLEWEED_EFFECT_PUFF_DEFAULT   0x32d
#define TUMBLEWEED_EFFECT_SPAWN_COUNT    0x14
#define TUMBLEWEED_PARTFX_MODE_ACTIVE    2
#define TUMBLEWEED_SFX_BURST             0x27d
#define TUMBLEWEED_SFX_HIT_LOOP          0x451
#define TUMBLEWEED_HIT_PULSE_VOLUME_SLOT 0x1f
#define TUMBLEWEED_HIT_PULSE_PERIOD      6
#define TUMBLEWEED_HIT_PULSE_ALT_STYLE   3

#define TUMBLEWEED_EFFECT_FLAG_BURST     0x01
#define TUMBLEWEED_EFFECT_FLAG_PUFF      0x02
#define TUMBLEWEED_EFFECT_FLAG_DESPAWN   0x04
#define TUMBLEWEED_EFFECT_FLAG_HIT_PULSE 0x10

#define TUMBLEWEED_PHASE_GROWING    0
#define TUMBLEWEED_PHASE_ARMED      1
#define TUMBLEWEED_PHASE_ROLLING    2
#define TUMBLEWEED_PHASE_DESPAWNING 5
#define TUMBLEWEED_PHASE_HOMING     6

typedef struct BackpackState {
    u8 unk0[0x268 - 0x0];
    u16 distToTarget;
    s16 triggerRange;
    f32 targetScale;
    union {
        f32 growRate;
        f32 despawnTimer;
    };
    u8 unk274[0x278 - 0x274];
    union {
        struct {
            u8 phase;
            u8 variant;
            u8 flags;
            u8 hitPulseCounter;
        };
        struct {
            u8 mode;
            u8 variantAlias;
            u8 effectFlags;
            u8 hitPulseCounterAlias;
        };
    };
    s16 recoilVelX;
    s16 recoilVelZ;
    u8 unk280[0x284 - 0x280];
    int* targetObj;
    f32 anchorPosX;
    f32 anchorPosZ;
    f32* targetPos;
    f32 speed;
    s16 triggerGameBit;
    s16 pickupMsgValue;
    f32 unk29C;
    f32 phaseTimer;
    u8 unk2A4[0x2A8 - 0x2A4];
} BackpackState;

/* Both names describe the same complete extra record. */
typedef BackpackState TumbleweedState;

STATIC_ASSERT(sizeof(BackpackState) == 0x2A8);
STATIC_ASSERT(offsetof(BackpackState, distToTarget) == 0x268);
STATIC_ASSERT(offsetof(BackpackState, triggerRange) == 0x26A);
STATIC_ASSERT(offsetof(BackpackState, targetScale) == 0x26C);
STATIC_ASSERT(offsetof(BackpackState, growRate) == 0x270);
STATIC_ASSERT(offsetof(BackpackState, phase) == 0x278);
STATIC_ASSERT(offsetof(BackpackState, variant) == 0x279);
STATIC_ASSERT(offsetof(BackpackState, flags) == 0x27A);
STATIC_ASSERT(offsetof(BackpackState, hitPulseCounter) == 0x27B);
STATIC_ASSERT(offsetof(BackpackState, recoilVelX) == 0x27C);
STATIC_ASSERT(offsetof(BackpackState, targetObj) == 0x284);
STATIC_ASSERT(offsetof(BackpackState, anchorPosX) == 0x288);
STATIC_ASSERT(offsetof(BackpackState, anchorPosZ) == 0x28C);
STATIC_ASSERT(offsetof(BackpackState, targetPos) == 0x290);
STATIC_ASSERT(offsetof(BackpackState, speed) == 0x294);
STATIC_ASSERT(offsetof(BackpackState, triggerGameBit) == 0x298);
STATIC_ASSERT(offsetof(BackpackState, pickupMsgValue) == 0x29A);
STATIC_ASSERT(offsetof(BackpackState, unk29C) == 0x29C);
STATIC_ASSERT(offsetof(BackpackState, phaseTimer) == 0x2A0);

void tumbleweed_updateRollingMotion(GameObject* obj, int state);
void tumbleweed_func0F(GameObject* obj, int value);
int tumbleweed_func0E(GameObject* obj);
void tumbleweed_render2(int* obj, int targetPos);
void tumbleweed_modelMtxFn(GameObject* obj);
void tumbleweed_func0B(GameObject* obj, float x, float y);
int tumbleweed_setScale(GameObject* obj);
int tumbleweed_getExtraSize(void);
void tumbleweed_free(int* obj);
void tumbleweed_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void tumbleweed_update(GameObject* obj);
void tumbleweed_updateStateMachine(GameObject* obj);
void tumbleweed_init(GameObject* obj, int defData);
void tumbleweed_updateEffects(GameObject* obj);
void tumbleweed_updateTargetedStateMachine(GameObject* obj);
int LandedArwing_ReturnZero(void);
int LandedArwing_TriggerLaunchTarget(int obj, int target);
int LandedArwing_UpdateBounceFade(int obj, u32* stateWord);
int LandedArwing_UpdateRetreatChase(GameObject* obj, int stateWord);
extern ObjectDescriptor16WithPadding gTumbleweedObjDescriptor;

#endif /* MAIN_DLL_DLL_00D2_TUMBLEWEED_H_ */
