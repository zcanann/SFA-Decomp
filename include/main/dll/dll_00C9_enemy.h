#ifndef MAIN_DLL_DLL_00C9_ENEMY_H_
#define MAIN_DLL_DLL_00C9_ENEMY_H_

#include "game/objects/object.h"
#include "types.h"
#include "global.h"
#include "main/dll/duster_api.h"
#include "main/dll/curves_collision_state.h"
#include "main/objprint_character_api.h"
#include "main/objseq.h"

struct ModelLightStruct;
struct ObjModelChain;

/*
 * obj+0xB8 extra record for the generic enemy family (DLL 0xC9). The block is
 * enemy_getExtraSize() = 0x370 bytes; it is neither a BaddieState (0x35C) nor a
 * TrickyState (0x83C), and the field set below is the one Baddie.c itself
 * reads and writes.
 */
typedef struct EnemyState {
    u8 unk0[0x4 - 0x0];
    /*
     * 0x004..0x26C is a CurvesCollisionState, the same aliasing BaddieState
     * carries: DLL 21 writes the region through the curves names and the
     * baddie code reads it back through the padded view below.
     */
    union {
        CurvesCollisionState curvesCollision;
        struct {
    u32 flags; /* head word of the embedded gPathControlInterface record at +4 */
    u8 unk8[0x19C - 0x8];
    s16 spawnRotY; /* engine-maintained pitch pair; the family handlers restore anim.rotY/rotZ from it after a move change */
    s16 spawnRotZ;
    u8 unk1A0[0x1B8 - 0x1A0];
    f32 nearestSpecialDeltaY; /* signed dy to the nearest type-0xe special-surface floor hit */
    u8 unk1BC[0x25F - 0x1BC];
    s8 physicsActive; /* floor-response pass enables the per-frame ground snap / footstep audio */
    u8 unk260;
    u8 bboxTraceFlags; /* bbox trace filter handed to trackGetLineIntersect */
    u8 unk262[0x264 - 0x262];
    s8 surfaceFlags; /* ENEMY_SURFACE_FLAG_* */
    u8 unk265[0x26C - 0x265];
        };
    };
    CharacterEyeAnimState eyeAnimState;
    u8 unk294[0x29C - 0x294];
    GameObject* trackedObj; /* current engagement target */
    u16 turnOctant; /* (u16 turnAngleDelta >> 13): which 1/8 sector the turn falls in */
    u16 turnAngleDelta; /* signed angle to trackedObj minus world rotX, normalized to +/-0x8000 */
    u16 targetDist; /* (s16) distance to trackedObj */
    u16 targetHeightDelta; /* (s16)(trackedObj.worldPosY - self.worldPosY) */
    f32 aggroRange; /* engagement range derived from placement data */
    f32 sightRange; /* patrol/detection range used by curve setup */
    u16 current;    /* numerator used by enemy_getHealthFraction */
    u16 max;        /* spawn-time denominator */
    s16 spawnedWeaponRomDefNo; /* romDefNo of the weapon child currently attached (-1 none) */
    s16 weaponRomDefNo; /* romDefNo of the weapon child that should be attached (-1 none) */
    f32 lookDirX; /* look/aim direction: yaw = getAngle(-X,-Z), pitch = getAngle(Y, hyp(X,Z)) */
    f32 lookDirY;
    f32 lookDirZ;
    f32 prevLookDirX;
    f32 prevLookDirY;
    f32 prevLookDirZ;
    f32 freezeEffectTimer; /* counts down by timeDelta; on reaching 0 the ice shatter fx re-fires and it re-primes to 20 */
    f32 repeatHitCooldown; /* counts down by timeDelta; while >= 0 a repeat hit of kind 0x1a is ignored */
    f32 freezeRecoverTimer;
/* controlFlags bit: the baddie is currently driven by the sequence-object /
 * script move system (set by newseqobj.c when a seq timer expires; gates the
 * scripted anim-chain moves, and makes the defeat handler skip the death
 * gamebits so scripted/cutscene deaths don't count). */
#define BADDIE_CONTROL_SEQUENCE_DRIVEN 0x40000000
/* controlFlags bit: the baddie follows its ROM curve path (RomCurveWalker).
 * Gates the path-tracking branches; cleared on hit/redirect. Also tested
 * against flags2E4 by the near/mid/far engagement ladder. */
#define BADDIE_CONTROL_PATH_FOLLOW 0x2000
/* controlFlags bit: a scripted move was just triggered this frame (the
 * newseqobj move system latches it before it promotes to SEQUENCE_DRIVEN). */
#define BADDIE_CONTROL_JUST_TRIGGERED 0x80000000
    u32 controlFlags;
    u32 prevControlFlags; /* controlFlags snapshot taken at the top of enemy_update; (cur & bit) && !(prev & bit) = bit raised this frame */
    u32 flags2E4;
    u32 flags2E8;
    u16 hitStunFrames; /* hit-reaction duration base handed over by the player attack descriptor (always 0x78); the crawler seeds its emerge timer with 2x/6x it */
    u8 unk2EE[0x2EF - 0x2EE];
    u8 actionId; /* current action selector (0..5) */
    u8 prevActionId; /* previous frame's actionId */
    u8 flags2F1; /* decoded player-attack flags (baddie_decodePlayerAttackFlags) */
    u8 curveIndex;
    u8 curveParamA;
    u8 curveParamB;
    u8 spawnBits; /* reward-drop selector decoded from the player attack flags */
    u8 frozenFadeCounter : 5; /* countdown gating the frozen-shatter fade-in sfx */
    u8 unk2F6 : 3;
    u8 unk2F7[0x2F8 - 0x2F7];
    u16 animEventMask; /* per-frame bitmask OR'd from (1 << anim event index); fed to objAudioFn */
    u8 unk2FA[0x2FC - 0x2FA];
    f32 pathStep; /* configured rom-curve advance step, seeded from EnemyPlacement.pathStepByte / 255 and then scaled by each family's init; pathSpeed is the per-frame value derived from it */
    f32 gravity; /* fall acceleration: velocityY -= gravity*dt, posY -= 0.5*gravity*dt^2 */
    f32 drag; /* per-second velocity damping base: velocity *= powfBitEstimate(drag, dt) */
    f32 animPlaySpeed; /* play speed handed to ObjAnim_AdvanceCurrentMove */
    f32 particleScale;
    f32 pathSpeed; /* rom-curve advance step (fed to Curve_AdvanceAlongPath, floored at 0.25) */
    f32 moveSpeedScale0; /* animPlaySpeed = 1 / (60 * scale) for moveId0 */
    f32 moveSpeedScale1; /* paired with moveId1 */
    f32 moveSpeedScale2; /* paired with moveId2 */
    u8 moveId0; /* ObjAnim_SetCurrentMove move id used when the baddie respawns */
    u8 moveId1; /* move id used by the defeat handler */
    u8 moveId2;
    u8 rootMotionFlags; /* which axes the current move drives from root motion: 1 Z, 2 X, 4 Y, 8 yaw */
    /* 0x324-0x333: four per-family f32 scratch slots. enemy_init zeroes all
     * four and the generic DLL never reads them again; every family handler in
     * 202.c gives them its own meaning, so the views are spelled out here
     * rather than re-declared with a private pad in each family's own struct. */
    union {
        struct {
            f32 unk324;
            f32 unk328;
            f32 unk32C;
            f32 unk330;
        };
        struct {
            f32 engineTimer;
            f32 emergeTimer;
            f32 distToCurve;
            f32 warpTimer;
        } crawler;
        struct {
            f32 approachTimer;
            f32 retreatTimer;
            f32 recoverTimer;
            f32 gruntTimer;
        } weevil;
        struct {
            f32 eventDelayTimer; /* delay before the next flags2F1 anim event: refilled intervalTimer + randomGetRange from the family table */
            f32 seqTimer; /* 16B-SeqEntry hold countdown; while nonzero with phaseAngle set the event controller is locked out; expiry chains phaseAngle via row+0xa/+0xb */
            f32 moveHoldTimer; /* event-move hold countdown; sets controlFlags 0x40 while running, restores BADDIE_CONTROL_SEQUENCE_DRIVEN on expiry */
            f32 moveHoldDuration; /* initial moveHoldTimer value (60 * blendScale * row blend); a hit while the move runs resets moveHoldTimer to it */
        } sharpClaw;
        struct {
            f32 phaseTimer;
            f32 decoyTimer;
        } duster;
        struct {
            f32 trackTimer;
            f32 breathTimer;
            f32 anchorY;
            f32 rippleTimer; /* baddieSpawnWaterRipple countdown: init 30, reset randomGetRange(30,60), spawns a water ripple at anchorY on expiry */
        } fireflyLantern;
        struct {
            f32 idleTimer;   /* vambat_updateIdle: += timeDelta, wraps at 360 clearing flags2E4 0x10000 (re-allows engagement) */
            f32 heartbeatSfxTimer; /* countdown reset to 60, plays SFXTRIG_mn_heart1_c on expiry */
            f32 engagedTimer; /* vambat_updateEngaged: += timeDelta; >360 or line-of-sight lost sets flags2E4 0x10000 and disengages */
        } vambat;
        struct {
            u8 pad324[8];
            f32 cooldownTimer; /* light-off countdown: seeded from placement +0x2C on powerdown msg, or gGcRobotPatrolCatchCooldown after catching the player; light child freed while >0, flags2E4 0x20 restored on expiry */
        } gcRobot;
        struct {
            f32 sfxTimer; /* kooshy_updateIdle: countdown, init 150, reset randomGetRange(150,300), plays SFXTRIG_sc_clubswipe on expiry */
        } kooshy;
        struct {
            f32 idleTimer; /* pinPon_updateIdle: += timeDelta, wraps at 360 clearing flags2E4 0x10000 (same idiom as vambat.idleTimer) */
        } pinPon;
        struct {
            f32 orbitCenterX; /* centre of the hover circle, seeded from the spawn position */
            f32 homeY; /* spawn height; the descend/ascend phases bracket it */
            f32 orbitCenterZ;
            f32 loopSfxTimer; /* countdown reset to 60, plays SFXTRIG_id_24a on expiry */
        } mikaladon;
    };
    f32 intervalTimer;
    u16 phaseAngle;
    /* 0x33A/0x33B: two per-family scratch bytes. The generic DLL only zeroes
     * them; the family handlers in 202.c disagree completely on what they hold.
     * 0x33A is a 16B-SeqEntry index (seqObj11D), a 12B-move-table index
     * (duster_wb/snowworm/hagabon/seqObj11E), a chain-node index (fireCrawler),
     * a day/night tri-state (duster), a countdown (kooshy) and a free-running
     * angle phase seeded randomGetRange(0, 0xff) and read (f32)(u32)
     * (fireflyLantern, which also steps it signed via *(char*)&). 0x33B is the
     * gBaddieFamilyTables/gBaddieFamilySpeedScales row index for the sharpClaw
     * cluster, an ObjGroup-80 latch (baddieWhirlpool), a variant/anim index
     * (fireCrawler/newSeqObj/snowworm/wispBaddieSeq), a counter
     * (fireflyLantern), a 60-frame countdown (weevil), an f32-accumulating
     * timer (seqObj11E) and packed flag bits plus a 2-bit index
     * (kooshy/magicPlant). */
    u8 userData1;
    u8 userData2;
    /* 0x33C-0x33F: four more per-family scratch bytes, zeroed alongside
     * userData1/userData2. */
    union {
        u8 unk33C[4];
        struct {
            u8 flagsC;
            u8 flagsD;
            u8 moveChainIndex;
            u8 reactStep;
        } crawler;
        struct {
            u8 activeEventIndex; /* row index shared by the parallel 12-byte event tables (FamilyTable tbl8 in the controller, tbl24 in the hit handler) */
            u8 idleRow; /* 12-byte IdleRow index, chained through row+9 */
            u8 idleRowStarted;
        } sharpClaw;
    } familyData;
    GameObject* lastHitObject;
    /* 0x344: filled exactly by the wall-plane record; the rachnop/duster and
       firefly-lantern planar-movement helpers are its only users. */
    WallPlaneState wallPlane;
    struct ModelLightStruct* modelLight;
    struct ObjModelChain* tailSimHandle;
} EnemyState;

STATIC_ASSERT(sizeof(EnemyState) == 0x370);
STATIC_ASSERT(offsetof(EnemyState, curvesCollision) == 0x004);
STATIC_ASSERT(offsetof(EnemyState, eyeAnimState) ==
              offsetof(EnemyState, curvesCollision) + CURVES_COLLISION_STATE_SIZE);
STATIC_ASSERT(offsetof(EnemyState, flags) == 0x004);
STATIC_ASSERT(offsetof(EnemyState, prevLookDirX) == 0x2C4);
STATIC_ASSERT(offsetof(EnemyState, spawnRotY) == 0x19C);
STATIC_ASSERT(offsetof(EnemyState, nearestSpecialDeltaY) == 0x1B8);
STATIC_ASSERT(offsetof(EnemyState, pathStep) == 0x2FC);
STATIC_ASSERT(offsetof(EnemyState, unk324) == 0x324);
STATIC_ASSERT(offsetof(EnemyState, userData1) == 0x33A);
STATIC_ASSERT(offsetof(EnemyState, familyData) == 0x33C);
STATIC_ASSERT(offsetof(EnemyState, lastHitObject) == 0x340);
STATIC_ASSERT(offsetof(EnemyState, physicsActive) == 0x25F);
STATIC_ASSERT(offsetof(EnemyState, surfaceFlags) == 0x264);
STATIC_ASSERT(offsetof(EnemyState, eyeAnimState) == 0x26C);
STATIC_ASSERT(offsetof(EnemyState, trackedObj) == 0x29C);
STATIC_ASSERT(offsetof(EnemyState, aggroRange) == 0x2A8);
STATIC_ASSERT(offsetof(EnemyState, lookDirX) == 0x2B8);
STATIC_ASSERT(offsetof(EnemyState, freezeEffectTimer) == 0x2D0);
STATIC_ASSERT(offsetof(EnemyState, controlFlags) == 0x2DC);
STATIC_ASSERT(offsetof(EnemyState, actionId) == 0x2EF);
STATIC_ASSERT(offsetof(EnemyState, spawnBits) == 0x2F5);
STATIC_ASSERT(offsetof(EnemyState, animEventMask) == 0x2F8);
STATIC_ASSERT(offsetof(EnemyState, gravity) == 0x300);
STATIC_ASSERT(offsetof(EnemyState, moveSpeedScale0) == 0x314);
STATIC_ASSERT(offsetof(EnemyState, rootMotionFlags) == 0x323);
STATIC_ASSERT(offsetof(EnemyState, wallPlane) == 0x344);
STATIC_ASSERT(offsetof(EnemyState, modelLight) == 0x368);

typedef struct EnemyTargetSearchResult {
    GameObject* obj;
    u16 dist;
    u8 pad6[2];
} EnemyTargetSearchResult;

STATIC_ASSERT(sizeof(EnemyTargetSearchResult) == 8);

void enemyObjAnimUpdate(short* obj, EnemyState* state);
int enemy_SeqFn(GameObject* node, int unused, ObjSeqState* animUpdate);
int enemy_findNearbyEnemies(GameObject* obj, f32 radius, u8 flags, int maxCount, EnemyTargetSearchResult* results);
void tricky_handleDefeat(GameObject* obj, EnemyState* state);
void baddie_updateWhileFrozen(GameObject* obj, u8* state, u8 fromHit);
int baddie_spawnRewardDrops(GameObject* obj, int state, int spawnBits, u32 useAltMode, u32 mode);
void baddieInstantiateWeapon(GameObject* obj, EnemyState* state);
u8 baddie_canSeeTarget(GameObject* obj, EnemyState* state, void* from, void* to);
void baddie_updateSightQuadrants(GameObject* obj, EnemyState* state, f32 radius);
void enemy_setTrackedObj(GameObject* obj, GameObject* target);
void enemy_steerVelocityToward(GameObject* obj, void* state, f32* direction, f32 maxSpeed, f32 speedRange, f32 maxAngle,
                 u8 adjustGroundVelocity);
void baddieTurnTowardLookDir(GameObject* obj, void* state, int divisor, f32 rollScale, f32 pitchScale, u8 useScaledRoll);
void enemy_setHealthZero(GameObject* obj);
void enemy_trackPlayer(GameObject* obj);
u8 enemy_getFreezeRecoverSeconds(GameObject* obj);
void enemy_getCurveParams(GameObject* obj, int* outIdx, f32* outA, f32* outB);
void baddieTurnTowardPoint(GameObject* obj, void* state, f32 targetX, f32 targetZ, int divisor, int angleBias);
f32 enemy_getHealthFraction(GameObject* obj);
f32 sidekickToy_accelerateTowardTarget3D(GameObject* obj, f32 tx, f32 ty, f32 tz, f32 accel, f32 speedScale,
                                         f32 maxVel, f32 drag);
f32 sidekickToy_accelerateTowardTargetXZ(GameObject* obj, f32 tx, f32 ty, f32 tz, f32 accel, f32 speedScale,
                                         f32 maxVel, f32 drag);
void sidekickToy_updateCurveTargetLatch(GameObject* obj);
void baddieAfterUpdateBonesCb(GameObject* obj, struct ObjModel* bones);
int enemy_getExtraSize(void);
int enemy_getObjectTypeId(void);
void enemy_release(void);
void enemy_initialise(void);
void enemy_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void enemy_hitDetect(GameObject* obj);
void enemy_free(GameObject* obj, int flag);
void enemy_update(GameObject* obj);
void enemy_init(GameObject* obj, u8* setup, int flag);

#endif /* MAIN_DLL_DLL_00C9_ENEMY_H_ */
