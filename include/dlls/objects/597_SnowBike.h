#ifndef DLLS_OBJECTS_597_SNOWBIKE_H_
#define DLLS_OBJECTS_597_SNOWBIKE_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_setup.h"
#include "types.h"
#include "global.h"

#include "dolphin/mtx/vec_types.h"
#include "game/objects/object.h"
#include "main/checkpoint_interface.h"
#include "main/checkpoint_route.h"
#include "main/dll/curves_collision_state.h"
#include "main/objseq.h"
#include "main/vecmath.h"

typedef struct SnowBikeFlags {
    u8 airborne : 1;       /* 0x80 */
    u8 accelerating : 1;   /* 0x40 */
    u8 airMeterActive : 1; /* 0x20 */
    u8 braking : 1;        /* 0x10 */
    u8 raceActive : 1;     /* 0x08 */
    u8 finished : 1;       /* 0x04 */
    u8 cpuDriven : 1;      /* 0x02 */
    u8 routeAnchored : 1;  /* 0x01 */
} SnowBikeFlags;

typedef struct SnowBikeTrailPoint {
    f32 x;
    f32 y;
    f32 z;
    s16 alpha;
    u8 surfaceType;
    u8 pad0F;
} SnowBikeTrailPoint;

typedef struct SnowBikeTrail {
    SnowBikeTrailPoint* points;
    s16 count;
    u8 flags;
    u8 pad07;
} SnowBikeTrail;

typedef struct SnowBikeState {
    MatrixTransform routeCursor; /* 0x000: heading and position sampled from the checkpoint route */
    f32 cpuSpeedFarDist;         /* 0x018 */
    f32 cpuSpeedNearDist;        /* 0x01c */
    f32 cpuSpeedFar;             /* 0x020: cpu target speed when far from the leader */
    f32 cpuSpeedNear;            /* 0x024: cpu target speed when near the leader */
    union {
        CheckpointRouteState routeState;
        CheckpointRankItem rankItem;
        struct {
            u8 pad028[0x4];
            s16 riderYawOnFree;   /* 0x02c */
            s16 riderPitchOnFree; /* 0x02e */
        };
    };
    f32 riderPosX;      /* 0x04c */
    f32 riderPosY;      /* 0x050 */
    f32 riderPosZ;      /* 0x054 */
    u8 routeBranchFlag; /* 0x058 */
    u8 pad059[0x3];
    u8 routeFilter; /* 0x05c */
    u8 routeMode;   /* 0x05d */
    u8 pad05E[0x2];
    s16* raceGameBits; /* 0x060: race started / finished gamebit pair */
    u8 pad064[0x1];
    s8 collisionHitType; /* 0x065: -1 = plain local point collision */
    u8 pad066[0x2];
    f32 wrongWayTimer;              /* 0x068 */
    f32 yawMatrix[16];              /* 0x06c */
    f32 invYawMatrix[16];           /* 0x0ac */
    f32 headingMatrix[16];          /* 0x0ec */
    f32 invHeadingMatrix[16];       /* 0x12c */
    f32 prevPosX;                   /* 0x16c */
    f32 prevPosY;                   /* 0x170 */
    f32 prevPosZ;                   /* 0x174 */
    CurvesCollisionState pathState; /* 0x178 */
    f32 impactVelScale;             /* 0x3e0 */
    f32 impactTimer;                /* 0x3e4 */
    f32 attachPosX;                 /* 0x3e8: rider attach point in world space */
    f32 attachPosY;                 /* 0x3ec */
    f32 attachPosZ;                 /* 0x3f0 */
    f32 rumbleVolume;               /* 0x3f4 */
    f32 jetsVolume;                 /* 0x3f8 */
    u8 pad3FC[0x4];
    f32 cameraPosX; /* 0x400 */
    f32 cameraPosY; /* 0x404 */
    f32 cameraPosZ; /* 0x408 */
    s16 velYaw;     /* 0x40c: direction of travel, chases yaw */
    s16 yaw;        /* 0x40e */
    s32 rollOffset; /* 0x410 */
    f32 yawVel;     /* 0x414 */
    u8 pad418[0x4];
    s16 savedRotY;    /* 0x41c */
    s16 savedRotZ;    /* 0x41e */
    u8 playerInRange; /* 0x420 */
    s8 mountState;    /* 0x421 */
    s8 raceRank;      /* 0x422 */
    u8 pad423;
    f32 airTime;         /* 0x424 */
    SnowBikeFlags flags; /* 0x428 */
    u8 pad429[0x3];
    GameObject* collidedObject; /* 0x42c */
    f32 throttle;               /* 0x430: negative drives forward */
    u8 bikeType;                /* 0x434: 0 = CloudRunner bike, 1 = Ice Mountain bike */
    u8 bikeVariant;             /* 0x435 */
    u8 pad436[0x2];
    f32 unk438;             /* 0x438 */
    f32 surfaceRumbleTimer; /* 0x43c */
    u16 engineSfxId;        /* 0x440 */
    u8 pad442[0x6];
    s16 completionGameBit; /* 0x448 */
    s16 finishedGameBit;   /* 0x44a */
    s16 steerAngleDeg;     /* 0x44c */
    u8 pad44E[0x2];
    u32 buttonsJustPressed;          /* 0x450 */
    u32 buttonsJustPressedIfNotBusy; /* 0x454 */
    u32 buttonsHeld;                 /* 0x458 */
    f32 stickX;                      /* 0x45c */
    s8 stickY;                       /* 0x460 */
    s8 unk461;                       /* 0x461 */
    u8 pad462[0x2];
    Vec velLimit;      /* 0x464 */
    Vec baseVelLimit;  /* 0x470 */
    Vec localVelLimit; /* 0x47c */
    u8 pad488[0xc];
    Vec localVel;             /* 0x494: bike-space velocity, -z is forward */
    Vec thrust;               /* 0x4a0 */
    f32 collisionBounceScale; /* 0x4ac */
    f32 gravity;              /* 0x4b0 */
    u8 groundSurfaceType;     /* 0x4b4 */
    u8 pad4B5[0x3];
    f32 airMeterMax;                /* 0x4b8 */
    f32 airMeterCurrent;            /* 0x4bc */
    f32 airDrainRate;               /* 0x4c0 */
    f32 airMeterRefillTimer;        /* 0x4c4 */
    SnowBikeTrail trails[9];        /* 0x4c8 */
    SnowBikeTrail* activeTrails[3]; /* 0x510: trail currently fed by each emitter */
    f32 lastTrailPosX;              /* 0x51c */
    f32 lastTrailPosY;              /* 0x520 */
    f32 lastTrailPosZ;              /* 0x524 */
    u8 pad528[0x4];
    f32 turnAccel;      /* 0x52c */
    f32 turnDamping;    /* 0x530 */
    f32 turnVelLimit;   /* 0x534 */
    f32 throttleTarget; /* 0x538 */
    f32 brakeDecel;     /* 0x53c */
    f32 turnVelScale;   /* 0x540 */
    f32 turnForceGain;  /* 0x544 */
    f32 localVelXDamp;  /* 0x548 */
    f32 localVelZDamp;  /* 0x54c */
    f32 rollScale;      /* 0x550 */
    f32 rollGain;       /* 0x554 */
    f32 yawFollowGain;  /* 0x558 */
    u8 pad55C[0x10];
    f32 turnDampingAirborne;   /* 0x56c */
    f32 pitchDecel;            /* 0x570 */
    f32 turnVelLimitAirborne;  /* 0x574 */
    f32 yawFollowGainAirborne; /* 0x578 */
    f32 localVelXDampAirborne; /* 0x57c */
    f32 localVelZDampAirborne; /* 0x580 */
    f32 pitchVel;              /* 0x584 */
    s16 wobblePhaseY;          /* 0x588 */
    s16 wobblePhaseZ;          /* 0x58a */
    f32 wobbleAmpY;            /* 0x58c */
    f32 wobbleAmpZ;            /* 0x590 */
    f32 wobbleY;               /* 0x594 */
    f32 wobbleZ;               /* 0x598 */
} SnowBikeState;
STATIC_ASSERT(offsetof(SnowBikeState, routeState) == 0x28);
STATIC_ASSERT(offsetof(SnowBikeState, routeBranchFlag) == 0x58);
STATIC_ASSERT(offsetof(SnowBikeState, pathState) == 0x178);
STATIC_ASSERT(offsetof(SnowBikeState, impactVelScale) == 0x3E0);
STATIC_ASSERT(offsetof(SnowBikeState, velYaw) == 0x40C);
STATIC_ASSERT(offsetof(SnowBikeState, airTime) == 0x424);
STATIC_ASSERT(offsetof(SnowBikeState, flags) == 0x428);
STATIC_ASSERT(offsetof(SnowBikeState, engineSfxId) == 0x440);
STATIC_ASSERT(offsetof(SnowBikeState, localVel) == 0x494);
STATIC_ASSERT(offsetof(SnowBikeState, collisionBounceScale) == 0x4AC);
STATIC_ASSERT(offsetof(SnowBikeState, trails) == 0x4C8);
STATIC_ASSERT(offsetof(SnowBikeState, activeTrails) == 0x510);
STATIC_ASSERT(offsetof(SnowBikeState, turnAccel) == 0x52C);
STATIC_ASSERT(offsetof(SnowBikeState, wobbleY) == 0x594);
STATIC_ASSERT(sizeof(SnowBikeState) == 0x59C);

typedef struct SnowBikeSegmentTypes {
    s8 types[4];
} SnowBikeSegmentTypes;

typedef struct SnowBikePathSetup {
    Vec terrainPoints[4];
    f32 terrainRadii[4];
    Vec collisionPoint;
} SnowBikePathSetup;

typedef struct SnowBikeLeaderRankItem {
    CheckpointRankItem item;
    u8 pad20[0x18];
} SnowBikeLeaderRankItem;

typedef struct SnowBikeTrailTemplate {
    f32 points[18];
} SnowBikeTrailTemplate;

typedef struct SnowBikeRomListItem {
    ObjPlacement base;
    u8 pad18[0x29 - 0x18];
    u8 yawByte;
} SnowBikeRomListItem;

typedef struct SnowBikePlacement {
    ObjPlacement base;
    u8 yawByte;
    u8 cpuDriven;
    s16 completionGameBit;
    u8 routeFilter;
    u8 routeMode;
    s16 finishedGameBit;
    u8 pad20[0x24 - 0x20];
} SnowBikePlacement;

STATIC_ASSERT(sizeof(SnowBikeSegmentTypes) == 4);
STATIC_ASSERT(sizeof(SnowBikePathSetup) == 0x4C);
STATIC_ASSERT(offsetof(SnowBikePathSetup, terrainRadii) == 0x30);
STATIC_ASSERT(offsetof(SnowBikePathSetup, collisionPoint) == 0x40);
STATIC_ASSERT(sizeof(SnowBikeLeaderRankItem) == 0x38);
STATIC_ASSERT(sizeof(SnowBikeTrailTemplate) == 0x48);
STATIC_ASSERT(offsetof(SnowBikeRomListItem, yawByte) == 0x29);
STATIC_ASSERT(sizeof(SnowBikePlacement) == 0x24);
STATIC_ASSERT(offsetof(SnowBikePlacement, yawByte) == 0x18);
STATIC_ASSERT(offsetof(SnowBikePlacement, cpuDriven) == 0x19);
STATIC_ASSERT(offsetof(SnowBikePlacement, completionGameBit) == 0x1A);
STATIC_ASSERT(offsetof(SnowBikePlacement, routeFilter) == 0x1C);
STATIC_ASSERT(offsetof(SnowBikePlacement, routeMode) == 0x1D);
STATIC_ASSERT(offsetof(SnowBikePlacement, finishedGameBit) == 0x1E);

extern f32 gSnowBikeRouteDistGate;

void SnowBike_update(GameObject* obj);
void SnowBike_resetToRomListPosition(GameObject* obj);
void SnowBike_ResetDynamics(GameObject* obj, SnowBikeState* state);
s32 SnowBike_getRouteRank(GameObject* obj);
s32 SnowBike_isAtRankGate(GameObject* obj);
int SnowBike_SeqFn(GameObject* obj, int unused, ObjSeqState* seq);
void SnowBike_onSeqFree(GameObject* obj);
void SnowBike_buildOrientationMatrices(GameObject* obj, SnowBikeState* state);
void SnowBike_InitTuning(GameObject* obj, SnowBikeState* state);
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

void SnowBike_DrawTrails(GameObject* obj, SnowBikeState* state);
void SnowBike_UpdateTrails(GameObject* obj, SnowBikeState* state);
void SnowBike_UpdateEngineFx(GameObject* obj, SnowBikeState* state, f32 forwardSpeed, int yJoy, s8* unused,
                             u8 soundFlags);
f32 SnowBike_GetRouteIntensity(GameObject* obj, SnowBikeState* state);
int SnowBike_UpdateSwingBlend(GameObject* obj, SnowBikeState* state);
int SnowBike_UpdateAttachedPosition(GameObject* obj, SnowBikeState* state);
void SnowBike_UpdateRouteFollowing(GameObject* obj, SnowBikeState* state);
void SnowBike_UpdateAirMeter(GameObject* obj, SnowBikeState* state);
void SnowBike_UpdateCollisionResponse(GameObject* obj, SnowBikeState* state);
void SnowBike_UpdateSteering(GameObject* obj, SnowBikeState* state);
void SnowBike_UpdateExhaustFx(GameObject* obj, SnowBikeState* state);

void SnowBike_UpdateLiftSway(GameObject* obj, SnowBikeState* state);
void SnowBike_func17(void);
void SnowBike_func16(void);
s32 SnowBike_getRacePosition(GameObject* obj);
s32 SnowBike_getMountState(GameObject* obj);
int SnowBike_getDismountSide(void);
int SnowBike_canDismount(void);
u8 SnowBike_getMountSide(GameObject* obj);
int SnowBike_getExtraSize(void);
int SnowBike_getObjectTypeId(void);
void SnowBike_init(GameObject* obj, SnowBikePlacement* params, int flag);

extern ObjectDescriptor24 gSnowBikeObjDescriptor;

#endif /* DLLS_OBJECTS_597_SNOWBIKE_H_ */
