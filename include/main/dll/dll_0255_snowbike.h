#ifndef MAIN_DLL_DLL_0255_SNOWBIKE_H_
#define MAIN_DLL_DLL_0255_SNOWBIKE_H_

#include "types.h"
#include "global.h"

#include "game/objects/object.h"
#include "main/checkpoint_interface.h"
#include "main/checkpoint_route.h"
#include "main/dll/curves_collision_state.h"
#include "main/objseq.h"

typedef struct SnowBikeRouteFlags {
    u8 resetLatch : 1;   /* 0x80 */
    u8 pathActive : 1;   /* 0x40 */
    u8 uiPrompt : 1;     /* 0x20 */
    u8 impulseLatch : 1; /* 0x10 */
    u8 active : 1;       /* 0x08 */
    u8 b04 : 1;          /* 0x04 */
    u8 b02 : 1;          /* 0x02 */
    u8 positionAnchored : 1; /* 0x01 */
} SnowBikeRouteFlags;

/* Per-object extra state for the rideable SnowBike / CloudRunner bike.
 * Offsets recovered from SnowBike_init/SnowBike_update derefs; the
 * 0x178..0x3DC block is the gPathControlInterface curves-collision state
 * and routeFlags at 0x428 carries the route/ride bits. */
typedef struct SnowBikeTrailPointPair
{
    f32 startX;
    f32 startY;
    f32 startZ;
    s16 startAlpha;
    u8 startColorByte;
    u8 pad0F;
    f32 endX;
    f32 endY;
    f32 endZ;
    s16 endAlpha;
    u8 endColorByte;
    u8 pad1F;
} SnowBikeTrailPointPair;

typedef struct SnowBikeTrail
{
    SnowBikeTrailPointPair* points;
    s16 count;
    u8 flags;
    u8 pad07;
} SnowBikeTrail;

typedef struct SnowBikeState {
    s16 savedRotX;          /* 0x000: saved anim.rotX on mount (restored on dismount) */
    u8 pad002[0xa];
    f32 posSnapshotX;       /* 0x00c: position snapshot X */
    f32 posSnapshotY;       /* 0x010: position snapshot Y */
    f32 posSnapshotZ;       /* 0x014: position snapshot Z */
    f32 unk018;             /* 0x018 */
    f32 unk01C;             /* 0x01c */
    f32 unk020;             /* 0x020 */
    f32 unk024;             /* 0x024 */
    union {
        CheckpointRouteState routeState;
        CheckpointRankItem rankItem;
        struct {
            u8 pad028[0x4];
            s16 riderYawOnFree;             /* 0x02c: rider yaw on free */
            s16 riderPitchOnFree;           /* 0x02e: rider pitch on free */
            u8 pad030[0x4];
            f32 unk034;                     /* 0x034 */
            int checkpointIndexA;           /* 0x038 */
            int checkpointIndexB;           /* 0x03c */
            int checkpointIndexC;           /* 0x040 */
            int unk044;                     /* 0x044 */
            u8 pad048[0x4];
        };
    };
    f32 riderPosX;             /* 0x04c: rider pos X on free */
    f32 riderPosY;             /* 0x050: rider pos Y on free */
    f32 riderPosZ;             /* 0x054: rider pos Z on free */
    u8 unk058;              /* 0x058 */
    u8 pad059[0x3];
    u8 routeFilter;         /* 0x05c: checkpoint route filter from object params */
    u8 routeMode;           /* 0x05d: advanceRoute mode argument, from object params */
    u8 pad05E[0x2];
    s16 *gameBitPtr;        /* 0x060: points to a pair of GameBit ids */
    u8 pad064[0x1];
    s8 collisionHitType;    /* 0x065: path-collision secondaryHitType (-1 = use plain non-Ex setup) */
    u8 pad066[0x2];
    f32 pathProgress;             /* 0x068 */
    f32 matrix06C[16];
    f32 matrix0AC[16];
    f32 matrix0EC[16];
    f32 matrix12C[16];
    f32 refPosX;             /* 0x16c: position reference X */
    f32 refPosY;             /* 0x170: position reference Y */
    f32 refPosZ;             /* 0x174: position reference Z */
    CurvesCollisionState pathState; /* 0x178 */
    f32 collisionFxDamping;             /* 0x3e0 */
    f32 collisionFxTimer;             /* 0x3e4 */
    f32 modelMtxPosX;       /* 0x3e8: model matrix position */
    f32 modelMtxPosY;       /* 0x3ec */
    f32 modelMtxPosZ;       /* 0x3f0 */
    f32 unk3F4;             /* 0x3f4 */
    f32 unk3F8;             /* 0x3f8 */
    u8 pad3FC[0x4];
    f32 mountPosX;          /* 0x400: local position latched at mount */
    f32 mountPosY;          /* 0x404 */
    f32 mountPosZ;          /* 0x408 */
    s16 yawCurrent;             /* 0x40c: yaw current */
    s16 yaw;             /* 0x40e: yaw target */
    int unk410;             /* 0x410 */
    f32 unk414;             /* 0x414: signed steer/lean value, read scaled by 1/400 and sign-tested */
    u8 pad418[0x4];
    s16 savedRotY;             /* 0x41c: saved anim.rotY (restored after temp halo modify) */
    s16 savedRotZ;             /* 0x41e: saved anim.rotZ (restored after temp halo modify) */
    u8 playerInRange;       /* 0x420: 1 while the mount hitbox reports INTERACT_FLAG_IN_RANGE, else 0; forced 0 once GAMEBIT_DIM_CrossedBlizzard is set; returned by the SnowBike_getMountSide vtable getter */
    s8 riderMode;              /* 0x421: rider mode */
    s8 routeRank;           /* 0x422: current checkpoint-route rank */
    u8 pad423;
    f32 impactShakeTimer;   /* 0x424: accumulates timeDelta while grounded; drives doRumble + CameraShake_SetOffset */
    SnowBikeRouteFlags routeFlags; /* 0x428 */
    u8 pad429[0x3];
    GameObject* linkedObject;  /* 0x42c: linked object */
    f32 engineFxLevel;      /* 0x430: scaled down on each collision impact; negated and scaled to form the SnowBike_UpdateEngineFx intensity argument */
    u8 bikeType;              /* 0x434: bike kind */
    u8 bikeVariant;              /* 0x435: variant */
    u8 pad436[0x2];
    f32 unk438;             /* 0x438 */
    f32 timer;              /* 0x43c: countdown timer (decays by timeDelta, fires+resets at floor) */
    s16 modelId;             /* 0x440: model id */
    u8 pad442[0x6];
    s16 completionGameBit;  /* 0x448: gamebit set to 1 when the mount/ride completes (SnowBike_setMountState) */
    s16 gameBitId;             /* 0x44a: gamebit id */
    s16 steerAngleDeg;      /* 0x44c: stick steering angle in deg (getAngle/gSnowBikeBamToDeg); gates partfx in angle bands */
    u8 pad44E[0x2];
    u32 buttonsJustPressed;             /* 0x450 */
    u32 buttonsJustPressedIfNotBusy;             /* 0x454 */
    u32 buttonsHeld;             /* 0x458 */
    f32 stickX;             /* 0x45c */
    s8 stickY;              /* 0x460 */
    u8 pad461[0x3];
    f32 velLimitX;             /* 0x464 */
    f32 velLimitY;             /* 0x468 */
    f32 velLimitZ;             /* 0x46c */
    f32 baseVelLimitX;             /* 0x470: persistent base velocity limit; copied into velLimit*+localVel*Limit on reset */
    f32 baseVelLimitY;             /* 0x474 */
    f32 baseVelLimitZ;             /* 0x478 */
    f32 localVelXLimit;             /* 0x47c */
    f32 localVelYLimit;             /* 0x480 */
    f32 localVelZLimit;     /* 0x484: symmetric clamp bound applied to localVelZ */
    u8 pad488[0xc];
    f32 localVelX;             /* 0x494 */
    f32 localVelY;             /* 0x498 */
    f32 localVelZ;             /* 0x49c: local-frame velocity Z (PSVECMag/PSVECScale treat 0x494 as a Vec) */
    f32 liftOffsetX;
    f32 liftOffsetY;
    f32 liftOffsetZ;
    f32 collisionBounceScale; /* 0x4ac: collision velocity-retention scalar (localVel *= dot*collisionBounceScale + K on hit) */
    f32 liftAccel;          /* 0x4b0: vertical accel integrated into localVelY (localVelY += liftAccel*dt); also scales turn force */
    u8 dampPresetMode;      /* 0x4b4: latched mode (copied from unk230) selecting the spring-target preset in the damp update switch */
    u8 pad4B5[0x3];
    f32 airMeterMax;             /* 0x4b8 */
    f32 airMeterCurrent;             /* 0x4bc */
    f32 airDrainRate;             /* 0x4c0 */
    f32 airMeterRefillTimer; /* 0x4c4: counts down by rate*timeDelta (clamped [0,K]); while non-zero, refills airMeterCurrent */
    SnowBikeTrail trails[9]; /* 0x4c8: cloud-trail records (SnowBike_UpdateTrails walks them by raw stride) */
    SnowBikeTrail* activeTrails[3]; /* 0x510: the three head-trail slots (accessed raw - the spawn loop walks them via a running slot base) */
    f32 homePosX;             /* 0x51c: home X */
    f32 homePosY;             /* 0x520: home Y */
    f32 homePosZ;             /* 0x524: home Z */
    u8 pad528[0x4];
    f32 unk52C;             /* 0x52c */
    f32 unk530;             /* 0x530: exponentially smoothed toward unk56C (same idiom as localVelXDamp/localVelXDampTarget); never read outside its own update */
    f32 unk534;             /* 0x534: exponentially smoothed toward unk574; never read outside its own update */
    f32 unk538;             /* 0x538 */
    f32 unk53C;             /* 0x53c */
    f32 turnVelScale;       /* 0x540: smoothed scale on the strafe/turn velocity delta */
    f32 turnForceGain;      /* 0x544: smoothed gain (* unk4B0) on the strafe/turn force input */
    f32 localVelXDamp;      /* 0x548: smoothed base of powfBitEstimate(.,dt) damping localVelX */
    f32 localVelZDamp;  /* 0x54c: smoothed base of powfBitEstimate(.,dt) damping localVelZ */
    f32 unk550;             /* 0x550 */
    f32 unk554;             /* 0x554 */
    f32 unk558;             /* 0x558: exponentially smoothed toward a clamped unk578; never read outside its own update */
    u8 pad55C[0x10];
    f32 unk56C;             /* 0x56c: held target for unk530 (riding-paused state) */
    f32 unk570;             /* 0x570 */
    f32 unk574;             /* 0x574: held target for unk534 (riding-paused state) */
    f32 unk578;             /* 0x578: held target for unk558 (riding-paused state) */
    f32 localVelXDampTarget;     /* 0x57c: held target for localVelXDamp (riding-paused state) */
    f32 localVelZDampTarget; /* 0x580: held target for localVelZDamp (riding-paused state) */
    f32 unk584;             /* 0x584 */
    s16 haloDriftPhaseA;    /* 0x588: integrated phase, fed to mathSinf for halo-light drift */
    s16 haloDriftPhaseB;    /* 0x58a: integrated phase, fed to mathSinf for halo-light drift */
    f32 haloYawDrift;             /* 0x58c */
    f32 haloDriftAmpB;      /* 0x590: halo drift channel-B amplitude (decays via powfBitEstimate) */
    f32 haloPitchDrift;             /* 0x594: halo-light yaw drift */
    f32 haloDriftB;         /* 0x598: halo drift channel-B output (haloDriftAmpB * sin(phaseB)); added to anim.rotZ */
} SnowBikeState; /* extends to at least 0x59C (DRhightop/DRhalolight tail) */
STATIC_ASSERT(offsetof(SnowBikeState, trails) == 0x4C8);
STATIC_ASSERT(offsetof(SnowBikeState, activeTrails) == 0x510);
STATIC_ASSERT(offsetof(SnowBikeState, refPosX) == 0x16C);
STATIC_ASSERT(offsetof(SnowBikeState, collisionFxDamping) == 0x3E0);
STATIC_ASSERT(offsetof(SnowBikeState, impactShakeTimer) == 0x424);
STATIC_ASSERT(offsetof(SnowBikeState, routeFlags) == 0x428);
STATIC_ASSERT(offsetof(SnowBikeState, collisionBounceScale) == 0x4AC);
STATIC_ASSERT(offsetof(SnowBikeState, unk530) == 0x530);
STATIC_ASSERT(offsetof(SnowBikeState, haloPitchDrift) == 0x594);

extern f32 gSnowBikeRouteDistGate;

void SnowBike_update(GameObject* obj);
void SnowBike_resetToRomListPosition(GameObject* obj);
void SnowBike_ResetDynamics(int obj, int state);
s32 SnowBike_getRouteRank(GameObject* obj);
s32 SnowBike_isAtRankGate(GameObject* obj);
int SnowBike_SeqFn(GameObject* obj, int unused, ObjSeqState* seq);
void SnowBike_onSeqFree(GameObject* obj);
void SnowBike_buildOrientationMatrices(GameObject* obj, int state);
void SnowBike_InitTuning(GameObject* obj, int state);
f32 SnowBike_func13(GameObject* obj, f32* out);
void SnowBike_getPlayerAnim(GameObject* obj, f32* outFloat, s32* outBool);
void SnowBike_setMountState(GameObject* obj, int type);
void SnowBike_getCameraPosition(GameObject* obj, f32* x, f32* y, f32* z);
void SnowBike_getRiderPosition(GameObject* obj, f32* x, f32* y, f32* z);
u32 SnowBike_canMount(GameObject* obj);
void SnowBike_free(GameObject* obj);
void SnowBike_render(GameObject* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible);
void SnowBike_hitDetect(GameObject* obj);
void SnowBike_release(void);
void SnowBike_initialise(void);

int SnowBike_UpdateSwingBlend(GameObject* obj, SnowBikeState* state);
int SnowBike_UpdateAttachedPosition(GameObject* obj, SnowBikeState* state);
void SnowBike_UpdateTrails(GameObject* obj, int state);
void SnowBike_UpdateEngineFx(GameObject* obj, void* state, f32 distanceScale, int intensity, u8* unused,
                             u8 channelFlags);
f32 SnowBike_GetRouteIntensity(GameObject* obj, int state);

#endif /* MAIN_DLL_DLL_0255_SNOWBIKE_H_ */
