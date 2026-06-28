#ifndef MAIN_DLL_ANDROSS_H_
#define MAIN_DLL_ANDROSS_H_

#include "ghidra_import.h"
#include "global.h"

/*
 * AndrossState - andross.c's obj+0xB8 extra record (andross_getExtraSize =
 * 0xEC). Field widths mirror the deref widths observed in andross.c;
 * unobserved ranges are padded.
 */
typedef struct AndrossState {
    int unk0;
    int handObjA; /* ObjList_FindObjectById(0x47b78); driven via androsshand_setState */
    int handObjB; /* ObjList_FindObjectById(0x47b6a); driven via androsshand_setState */
    int lightAnchorObj;
    int effectHandle;
    int unk14;
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
            int spawnObj[4];      /* 0x18: ObjList_FindObjectById(gAndrossSpawnObjectIds[i]) */
            SunVec3 spawnDelta[4]; /* 0x28: spawnObj[i] world pos - Andross local pos */
        };
        struct {
            u8 unk18[0x20 - 0x18];
            s16 unk20;
            u8 unk22[0x23 - 0x22];
            u8 unk23;
            u8 unk24[0x43 - 0x24];
            s8 unk43;
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
    f32 unkA8;
    u8 actionToggle;
    u8 signalFlags; /* |= signal (the setter param name) */
    u8 unkAE;
    u8 unkAF;
    u8 unkB0;
    u8 unkB1[0xB5 - 0xB1];
    u8 unkB5;
    u8 unkB6;
    u8 unkB7;
    int seqQueryObj; /* object handle queried via animatedObjGetSeqId */
    u8 unkBC;
    u8 unkBD[0xC0 - 0xBD];
    f32 cachedPosX;
    f32 cachedPosY;
    f32 cachedPosZ;
    f32 targetPosX; /* tracked target: K*sin(t) + homePos + clamped arwing delta */
    f32 targetPosY;
    f32 targetPosZ;
    f32 velX; /* horizontal velocity = clampedDist * sin(yaw), minus damped arwing vel */
    f32 velY; /* horizontal velocity = clampedDist * cos(yaw), minus damped arwing vel */
    f32 velZ;
    f32 soundTimer; /* += timeDelta; on threshold plays sfx 0x46f and latches a flag */
    u8 soundEventFlags;
    u8 unkE9[0xEC - 0xE9];
} AndrossState;

STATIC_ASSERT(sizeof(AndrossState) == 0xEC);
STATIC_ASSERT(offsetof(AndrossState, spawnObj) == 0x18);
STATIC_ASSERT(offsetof(AndrossState, spawnDelta) == 0x28);
STATIC_ASSERT(offsetof(AndrossState, targetPosPtr) == 0x4C);
STATIC_ASSERT(offsetof(AndrossState, homePosX) == 0x58);
STATIC_ASSERT(offsetof(AndrossState, actionTimer) == 0x98);

#endif /* MAIN_DLL_ANDROSS_H_ */
