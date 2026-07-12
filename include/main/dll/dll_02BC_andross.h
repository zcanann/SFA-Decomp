#ifndef MAIN_DLL_ANDROSS_H_
#define MAIN_DLL_ANDROSS_H_

#include "ghidra_import.h"
#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/vec_types.h"

/*
 * AndrossState - andross.c's obj+0xB8 extra record (andross_getExtraSize =
 * 0xEC). Field widths mirror the deref widths observed in andross.c;
 * unobserved ranges are padded.
 */
typedef struct AndrossState {
    GameObject* arwingObj;
    GameObject* handObjA; /* ObjList_FindObjectById(0x47b78); driven via androsshand_setState */
    GameObject* handObjB; /* ObjList_FindObjectById(0x47b6a); driven via androsshand_setState */
    GameObject* lightAnchorObj;
    GameObject* effectHandle;
    GameObject* spawnedObj;
    /*
     * 0x18..0x58 is genuinely a pair of per-spawn arrays on the Andross state
     * itself: four spawned-object handles followed by four position-delta
     * vectors (object world pos - Andross local pos, restored each tick).
     * The scalar overlay names below alias the same bytes only because the
     * code casts foreign objects (render ops, helper objects, freshly
     * allocated setups) through AndrossState* to reach those objects' own
     * fields - none of those scalar accesses are made on the Andross state.
     */
    union {
        struct {
            GameObject* spawnObj[4]; /* 0x18: ObjList_FindObjectById(gAndrossSpawnObjectIds[i]) */
            Vec3f spawnDelta[4]; /* 0x28: spawnObj[i] world pos - Andross local pos */
        };
        struct {
            u8 unk18[0x20 - 0x18];
            s16 unk20;
            u8 unk22[0x23 - 0x22];
            u8 handState;
            u8 unk24[0x43 - 0x24];
            s8 alpha;
            s16 unk44;
            u8 unk46[0x4C - 0x46];
            int targetPosPtr;
            u8 unk50[0x58 - 0x50];
        };
    };
    f32 homePosX; /* anchor position from the placement (setup->posX/Y/Z) */
    f32 homePosY;
    f32 homePosZ;
    f32 animSpeed; /* passed with ObjAnim_SetCurrentMove */
    f32 fadeAlpha; /* mesh alpha source (alpha = K * fadeAlpha) */
    f32 spawnCooldown;
    f32 savedPosZ; /* cached anim.localPosZ; restored and used as (savedPosZ - localPosZ) delta */
    f32 springStiffness; /* vel += stiffness * (targetPos - pos) */
    f32 springDamping; /* vel *= damping each tick */
    int fightPhase; /* phase switch (1/2/5/6...) */
    int prevFightPhase; /* change-detect latch for fightPhase */
    int actionPending; /* set when timers expire; drives the actionState switch */
    int actionState; /* main action state machine (switch 0..0xd) */
    int prevActionState; /* change-detect latch for actionState */
    int effectLifetime;
    int spawnedObjLifetime;
    s16 actionTimer; /* frames; -= framesThisStep, re-armed from config on expiry */
    u8 unk9A[0x9C - 0x9A];
    f32 durationTimer; /* seconds; -= timeDelta, compared to thresholds */
    s16 targetRotX; /* target pitch angle; sval = targetRotX - anim.rotX */
    s16 rotXSpeed; /* smoothed delta added to anim.rotX each tick */
    s16 rotYSpeed; /* smoothed delta added to anim.rotY each tick */
    s16 timer;
    f32 camOffsetAccum; /* eased camera offset: += rate*timeDelta (clamped both ways); read as camActionParam = base + this */
    u8 actionToggle;
    u8 signalFlags; /* |= signal (the setter param name) */
    union {
        u8 partHealth[4];
        struct {
            u8 hitsRemaining0; /* phase advances when the first three part health values reach zero */
            u8 hitsRemaining1;
            u8 hitsRemaining2;
            u8 centralHealth;
        };
    };
    union {
        u8 partHitTimer[4];
        struct {
            u8 unkB2[3];
            u8 hitReactionFlag; /* central-part hit timer; also drives the hurt/stagger action */
        };
    };
    u8 startupDelay; /* 0xB6: init to 5; update decrements and returns early until it hits 0 (spawn settle) */
    u8 attackCycleCount; /* 0xB7: repeat counter; phase advances after 3 attack cycles */
    union {
        int seqQueryObj;
        struct {
            u8 arwingFlightActive;
            s8 partTextureState[3];
        };
    };
    u8 handsInitialized; /* 0xBC: 1 at init; first phase-1 entry clears it and skips the hand reset */
    u8 unkBD[0xC0 - 0xBD];
    f32 cachedPosX;
    f32 cachedPosY;
    f32 cachedPosZ;
    f32 targetPosX; /* tracked target: K*sin(t) + homePos + clamped arwing delta */
    f32 targetPosY;
    f32 targetPosZ;
    union {
        struct {
            f32 velX; /* horizontal velocity = clampedDist * sin(yaw), minus damped arwing vel */
            f32 velY; /* horizontal velocity = clampedDist * cos(yaw), minus damped arwing vel */
            f32 velZ;
        };
        Vec3f velocity;
    };
    f32 soundTimer; /* += timeDelta; on threshold plays sfx 0x46f and latches a flag */
    union {
        u8 soundEventFlags;
        struct {
            u8 laughPlayed : 1;
            u8 ringPlayed : 1;
            u8 roarPlayed : 1;
        };
    };
    u8 unkE9[0xEC - 0xE9];
} AndrossState;

STATIC_ASSERT(sizeof(AndrossState) == 0xEC);
STATIC_ASSERT(offsetof(AndrossState, spawnObj) == 0x18);
STATIC_ASSERT(offsetof(AndrossState, spawnDelta) == 0x28);
STATIC_ASSERT(offsetof(AndrossState, targetPosPtr) == 0x4C);
STATIC_ASSERT(offsetof(AndrossState, homePosX) == 0x58);
STATIC_ASSERT(offsetof(AndrossState, actionTimer) == 0x98);
STATIC_ASSERT(offsetof(AndrossState, partHealth) == 0xAE);
STATIC_ASSERT(offsetof(AndrossState, partHitTimer) == 0xB2);
STATIC_ASSERT(offsetof(AndrossState, partTextureState) == 0xB9);

extern ObjectDescriptor gAndrossObjDescriptor;

extern f32 gAndrossMoveAnimSpeeds[23];
extern f32 gAndrossZero;
extern f32 gAndrossSwayAmplitudeX;
extern f32 gAndrossSwayAmplitudeY;
extern f32 gAndrossMissileClampRange;
extern f32 gAndrossMissileVelocityScale;
extern f32 gAndrossMissileForwardVelocity;
extern f32 gAndrossCentralMissileClampRange;
extern f32 gAndrossCentralMissileVelocityScale;
extern f32 gAndrossCentralMissileForwardVelocity;
extern f32 gAndrossArwingApproachVelocityScale;
extern f32 gAndrossSpawnRandX;
extern f32 gAndrossSpawnRandY;
extern f32 gAndrossSpawnRandZ;
extern f32 gAndrossSpawnOffsetY;
extern f32 gAndrossSpawnOffsetZ;
extern f32 gAndrossArwingReturnVelocityScale;
extern f32 gAndrossArwingPullProgressLimit;
extern f32 gAndrossArwingPullVelocityScale;
extern f32 gAndrossArwingThrustScale;
extern f32 gAndrossArwingRotationScale;
extern f32 gAndrossArwingReleaseProgressLimit;
extern f32 gAndrossArwingReleaseVelocityScale;
extern f32 gAndrossArwingReleaseThrustScale;
extern f32 gAndrossArwingReleaseRotationScale;
extern f32 gAndrossArwingFollowScale;
extern f32 gAndrossArwingFlightClampRange;
extern f32 gAndrossArwingFlightVelocityScale;
extern f32 gAndrossForwardDistanceThreshold;
extern f32 gAndrossArwingVelDamp;
extern f32 gAndrossRingProjectileScale;
extern f32 gAndrossDistortPhaseStep;
extern f32 gAndrossDistortPhaseReset;
extern f32 gAndrossDistortPhase;
extern int gAndrossSpawnObjectIds[4];
extern int gAndrossRotationTargetDivisor;
extern int gAndrossRotationSmoothingDivisor;
extern int gAndrossFlightHalfWidth;
extern int gAndrossRingSpawnInterval;
extern int gAndrossMissileAttackDuration;
extern int gAndrossMissileSpawnInterval;
extern int gAndrossCentralAttackDuration;
extern int gAndrossCentralMissileSpawnInterval;
extern int gAndrossAsteroidSpawnInterval;
extern int gAndrossBrainAttackDuration;
extern int gAndrossMoveTailDistance;
extern int gAndrossAimedProjectileSpeed;
extern int gAndrossAimedProjectileLifetime;
extern int gAndrossRingProjectileLifetime;
extern int gAndrossProjectileForwardStep;
extern int gAndrossSpawnedObjectLifetime;
extern s16 gAndrossSwayPhaseStepX;
extern s16 gAndrossSwayPhaseStepY;
extern s16 gAndrossSwayPhaseY;
extern s16 gAndrossSwayPhaseX;
extern u8 gAndrossPartTextureIndices[4];
extern u32 gAndrossDistortFilterParam;

void fn_80239DD8(GameObject* obj, AndrossState* state);
void fn_80239EAC(GameObject* obj, AndrossState* state);
void fn_80239FCC(GameObject* obj, AndrossState* state);
void fn_8023A168(GameObject* obj, AndrossState* state);
void fn_8023A268(GameObject* obj, AndrossState* state, int p3);
void fn_8023A3E4(GameObject* obj, AndrossState* state);
int fn_8023A6A4(AndrossState* state, f32 clampRange, f32 scale, f32 zVel);
void fn_8023A87C(GameObject* obj, AndrossState* state);

int andross_SeqFn(GameObject* obj);
int andross_getExtraSize(void);
int andross_getObjectTypeId(void);
void andross_free(int obj);
void andross_hitDetect(void);
void andross_render(int obj, int p2, int p3, int p4, int p5);
void andross_setPartSignal(GameObject* obj, u8 signal);
void andross_update(int obj);
void andross_init(int obj, ObjPlacement* setup);

#endif /* MAIN_DLL_ANDROSS_H_ */
