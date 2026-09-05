#ifndef MAIN_DLL_TRICKY_STATE_H_
#define MAIN_DLL_TRICKY_STATE_H_

#include "types.h"
#include "global.h"
#include "main/objprint_character_api.h"
#include "main/dll/curve_walker.h"
#include "main/dll/curves_collision_state.h"
#include "main/dll/objfsa.h"
#include "game/objects/object.h"
#include "main/objprint_sound_api.h"
#include "main/pi_dolphin_path_api.h"
#include "main/mapEventTypes.h"

#define TRICKY_FLAME_CHILD_COUNT 7

enum {
    TRICKY_ROUTE_CANDIDATE_COUNT = 8,
    TRICKY_PATH_SEARCH_CACHE_INDEX = TRICKY_ROUTE_CANDIDATE_COUNT,
    TRICKY_PATH_SEARCH_COUNT = TRICKY_ROUTE_CANDIDATE_COUNT + 1,
};

/* Tricky movement and command flags. */
#define TRICKY_STATE_FLAG_CHILDREN_ACTIVE  0x800  /* spawned child objects are active */
#define TRICKY_STATE_FLAG_CHILDREN_CLEANUP 0x1000 /* child objects torn down this cycle */
#define TRICKY_STATE_FLAG_MOVE_ADVANCING                                                                               \
    0x8000000 /* ObjAnim_AdvanceCurrentMove reported the current move still advancing */
#define TRICKY_STATE_FLAG_PATH_PATCHES_VALID 0x400 /* cached patch groups and positions describe targetPosPtr */
#define TRICKY_STATE_FLAG_COMMAND_ACTIVE     0x10  /* sidekick command/flame/dig/guard action is active */
#define TRICKY_STATE_FLAG_RECALL_REQUEST     0x10000
#define TRICKY_STATE_FLAG_HEEL_REQUEST       0x20000
#define TRICKY_STATE_FLAG_GUARD_REQUEST      0x40000

/* TrickyState.movementState - the walk/jump phase selector switched on in
 * trickyUpdateMovementState. The names come from the retained retail diagnostic
 * strings for each case ("walk wait", "walk free", "walk start patch",
 * "walk end patch", "walk patch exit", "curve setup", "walk to node",
 * "walk nodes", "Jump run up", "Jump prep", "Jumping", "Jump up run up",
 * "JUMPDOWN or JUMPUP", "JUMPDOWN_RUNUP"). The two states sharing the
 * "JUMPDOWN or JUMPUP" text are told apart by the sign of the verticalDelta
 * each one seeds: 0x0C climbs to the node, 0x0E descends to it. */
typedef enum TrickyMovementState {
    TRICKY_MOVE_WALK_WAIT = 0,
    TRICKY_MOVE_WALK_FREE = 1,
    TRICKY_MOVE_WALK_START_PATCH = 2,
    TRICKY_MOVE_WALK_END_PATCH = 3,
    TRICKY_MOVE_WALK_PATCH_EXIT = 4,
    TRICKY_MOVE_CURVE_SETUP = 5,
    TRICKY_MOVE_WALK_TO_NODE = 6,
    TRICKY_MOVE_WALK_NODES = 7,
    TRICKY_MOVE_JUMP_RUNUP = 8,
    TRICKY_MOVE_JUMP_PREP = 9,
    TRICKY_MOVE_JUMPING = 10,
    TRICKY_MOVE_JUMPUP_RUNUP = 11,
    TRICKY_MOVE_JUMPUP = 12,
    TRICKY_MOVE_JUMPDOWN_RUNUP = 13,
    TRICKY_MOVE_JUMPDOWN = 14,
} TrickyMovementState;

/* Tunnel entry/exit references are exchanged with a retail XOR swap. */
typedef union TrickyCurveReference {
    struct RomCurveDef* curve;
    u32 bits;
} TrickyCurveReference;

STATIC_ASSERT(sizeof(TrickyCurveReference) == 4);

typedef int (*TrickyFlameTargetCallback)(GameObject* obj, int amount);

typedef struct TrickyPackedSlots {
    u8 exclamationPromptSlot : 2;
    u8 questPromptSlot : 2;
    u8 foodChildSlot : 2;
    u8 unusedPromptSlotBits : 2;
} TrickyPackedSlots;

typedef enum TrickyCommandPhase {
    TRICKY_COMMAND_PHASE_IDLE = -1,
    TRICKY_COMMAND_PHASE_NONE = 0,
    TRICKY_COMMAND_PHASE_DIG = 1,
    TRICKY_COMMAND_PHASE_GUARD = 3,
    TRICKY_COMMAND_PHASE_FLAME = 4,
    TRICKY_COMMAND_PHASE_PLAY_BALL = 5,
} TrickyCommandPhase;

#define MAX_COMM_PRESENT 10

typedef struct TrickyCommand {
    GameObject* targetObj;
    s8 commandKind;
    s8 commandType;
    s8 ttlFrames;
    u8 pad7;
} TrickyCommand;

STATIC_ASSERT(offsetof(TrickyCommand, targetObj) == 0);
STATIC_ASSERT(offsetof(TrickyCommand, commandKind) == 4);
STATIC_ASSERT(offsetof(TrickyCommand, commandType) == 5);
STATIC_ASSERT(offsetof(TrickyCommand, ttlFrames) == 6);
STATIC_ASSERT(sizeof(TrickyCommand) == 8);

typedef struct TrickyJumpArc {
    f32 duration;  /* 0x00: horizontal distance / jump speed */
    f32 time;      /* 0x04: elapsed arc time (init 0, += timeDelta) */
    f32 riseCoeff; /* 0x08: linear vertical coefficient */
    f32 baseY;     /* 0x0C: launch worldPosY */
    f32 baseX;     /* 0x10: launch worldPosX */
    f32 baseZ;     /* 0x14: launch worldPosZ */
    f32 landX;     /* 0x18: landing node x */
    f32 landZ;     /* 0x1C: landing node z */
} TrickyJumpArc;

struct RomCurveDef;

/*
 * TrickyState - the obj+0xB8 extra record for the Tricky sidekick handlers.
 * DLL 21 owns the embedded collision record. Unobserved ranges are padded.
 * Tricky_getExtraSize returns 0x83C, including the final particle timer.
 */
typedef struct TrickyState {
    TrickyStats* stats;       /* persisted energy and ball-play statistics */
    GameObject* playerObj;    /* owning player/sidekick object */
    u8 stateIndex;            /* primary Tricky state selector (0..0x11), indexing the state handler table */
    u8 movementState;         /* TRICKY_MOVE_* path/jump phase selector */
    u8 substate;              /* per-state handler substate */
    u8 sideCommandPromptMask; /* transient sidekick command prompt bitmask:
                                 |= TRICKY_COMMAND_TYPE_TO_FLAG(commandType) when another object enables a command,
                                 OR'd with Call+Stay into the UI prompt mask, tested != 0, cleared to 0 (tricky) */
    u8 pad0C;
    s8 commandPhase; /* current command-dispatch phase selector (-1 idle, 1..5 active); compared == 3 / != 0 to gate the queued-command state machine (tricky/substates/weapone6/tumbleweedbush/mmp) */
    u8 padE[0x10 - 0xE];
    f32 prevSpeed;
    f32 speed; /* planar speed magnitude, multiplied into moveVector */
    f32 animTransitionTimer;
    u8 pad1C[0x20 - 0x1C];
    int moveId;            /* compared to anim.currentMove, passed to ObjAnim_SetCurrentMove */
    GameObject* followObj; /* the followed object (playerObj/target/found stores; dll vtable dispatched) */
    f32* targetPosPtr;     /* current target/path position (compared to previousTargetPosPtr; fed to pathSearchBegin) */
    struct {
        f32 x;
        f32 z;
    } moveVector;        /* unit direction for movement; full start-to-exit displacement while tunneling */
    f32 animRate;        /* normalized move-phase advance per timeDelta unit; zero uses arcMoveProgress */
    f32 pendingAnimRate; /* installed when moveId becomes the current animation */
    f32 arcMoveProgress; /* normalized jump-arc/tween progress (arc->time / arc->duration, clamped/eased); passed to ObjAnim_SetMoveProgress (trickyfollow sets, tricky reads) */
    f32 sidestepDelta;
    f32 backstepDelta;
    f32 verticalDelta;
    f32 rotStepScale;
    u32 pendingStateFlags;
    u32 stateFlags;
    union {
        u8 statusFlags;
        struct {
            u8 ownsWarpHelperObject : 1;
            u8 soundSuppressed : 1;
            u8 heightTracking : 1;
            u8 warpCooldown : 4;
            u8 unusedStatusFlag : 1;
        };
    };
    u8 pad59;
    s16 targetYaw;        /* facing target for TRICKY_STATE_FLAG_ROTATE */
    s32 heightTrackObjId; /* object ident being height-tracked; -1 while searching for a nearby XYZ animator */
    f32 trackedHeight;
    TrickyJumpArc jumpArc; /* 0x64: ballistic hop arc */
    u8 pad84[0x8C - 0x84];
    f32 prevLocalPosX;
    f32 prevLocalPosY;
    f32 prevLocalPosZ;
    s16 cachedPatchGroups[OBJFSA_PATCHGROUP_PATCH_COUNT];
    Vec cachedPatchPositions[OBJFSA_PATCHGROUP_PATCH_COUNT];
    u16 lastWalkGroup;    /* last nonzero walk group accepted by movement; retained during off-group traversal */
    s16 linkedPatchGroup; /* cached patch ID for linkedPatchPos; retail's update compares a group-index product */
    Vec linkedPatchPos;
    Vec recoveryPos; /* fallback position; seeded on relocation and refreshed while inside walkable areas */
    Vec patchExitPos;
    CurvesCollisionState curvesCollision;
    GameObject* lastContactObj;
    f32 contactTimer;
    int hitType;    /* current cooldown-filtered priority hit; zero when no hit is accepted */
    int modelChain; /* ObjModelChain handle toggled via ObjModelChain_SetEnabled */
    f32 hitCooldown;
    u8 groundSnapCounter; /* frame countdown that forces the ground-snap path: != 0 -> decrement and do the height snap; primed to 2 on state entry (tricky/skeetla) */
    u8 pad375[0x378 - 0x375];
    CharacterEyeAnimState
        eyeAnimState; /* 0x378: head-aim / eye-blink record; lookAtPos is followObj's captured world position */
    u8 pad3A0[0x3A8 - 0x3A0];
    ObjSoundState soundState;  /* 0x3A8: object-channel playback and mouth-animation state */
    Vec pathPointPositions[4]; /* ObjPath points 4..7 refreshed by Tricky_render */
    Vec mouthPos;              /* ObjPath point 8: carried ball, flame origin and mouth particles */
    s16 mouthYawOffset;        /* joint-pose Y rotation added to the flame's horizontal heading */
    u8 pad416[0x418 - 0x416];
    struct RomCurveDef* routeSeedNode; /* candidate route node chosen before seeding route */
    u8 routeSeedDirection;             /* 0 forward, 1 backward */
    u8 pad41D[0x420 - 0x41D];
    RomCurveWalker route;
    RomCurveDef* cachedRouteDef;      /* route selection is cached by node, walk group and direction */
    RomCurveDef* validatedRouteEntry; /* route entry pointer validated via trickyValidateRouteEntry */
    u16 cachedWalkGroup;              /* destination walk group used for validatedRouteEntry */
    u16 walkGroup;                    /* route destination walk group; may fall back during route selection */
    u16 savedWalkGroup;               /* destination snapshot taken before movement chooses a fallback route */
    u8 cachedRouteDirection;
    u8 pad537[1];
    PathSearch pathSearches[TRICKY_PATH_SEARCH_COUNT]; /* eight candidates and one cached route search */
    RomCurveDef* cachedRouteEntry;                     /* last point returned from the cached path search */
    int cachedTargetWalkGroup;                         /* target walk group of that path search */
    f32* previousTargetPosPtr;                         /* identity of the target whose position was saved last update */
    Vec previousTargetPos;
    union {
        struct {
            GameObject* fetchBallObj; /* sidekick ball object being fetched/returned */
            f32 fetchCarryDelayTimer;
            f32 fetchThrowRetryTimer;
        };
        struct {
            struct RomCurveDef* cannonballStartCurve;
            u8 cannonballPad704[4];
            f32 cannonballRollSfxTimer;
            u8 cannonballPad70C[4];
            f32 cannonballRandomValue; /* initialized on command entry; no recovered reader */
        };
        struct {
            struct RomCurveDef* digTunnelStartNode;
            TrickyCurveReference digTunnelExitNode;
            TrickyCurveReference digTunnelEntryNode;
            f32 digTunnelWhineTimer;
        };
        struct {
            s32 circlingDirection;
            union {
                s32 circlingAngle;
                u32 circlingAngleBits; /* unsigned view for the wrapped yaw difference */
            };
            Vec circlingTargetPos;
        };
        struct {
            u8 tumbleweedCount : 4;
            u8 unusedTumbleweedCountBits : 4;
            u8 tumbleweedPad701[3];
            f32 tumbleweedTargetX;
            f32 tumbleweedTargetY;
            f32 tumbleweedTargetZ;
            GameObject* tumbleweedTargetObj;
        };
        struct {
            f32 secretDigPressTimer;
            f32 secretDigOriginX;
            f32 secretDigOriginZ;
            struct RomCurveDef* secretDigCurve;
            f32 secretDigWhineTimer;
        };
        GameObject* flameChildren[TRICKY_FLAME_CHILD_COUNT]; /* staggered flameblasts retired as a group */
    };
    union {
        struct {
            f32 followHeelTimer; /* holds the closer heel radius and inhibits new ambient activities */
            f32 playerContactTimer;
            f32 idleTimer;
        };
        struct {
            f32 baddieBarkTimer;
            GameObject* baddieAlertTarget;
            GameObject* baddieAlertWarp; /* active trickywarp detour while tracking the alert target */
        };
        f32 guardPoint[3]; /* guard-post position: home position minus 15 units along facing */
        struct {
            struct RomCurveDef* flameEdgeNode;   /* trickyFlame: Objfsa_FindNearestCurveType24 result */
            struct RomCurveDef* flameReturnNode; /* trickyFlame: getById(flameEdgeNode->linkIds[0]) */
            TrickyFlameTargetCallback flameTargetCallback;
        };
    };
    union {
        struct {
            u8 idleActivityFlags; /* ambient-idle latches plus Thorntail approach voice/move latch */
            u8 pad729[0x72C - 0x729];
        };
        struct {
            u8 idleActivityPending : 1;
            u8 idleActivityDelayActive : 1;
            u8 thorntailIdleMovePending : 1;
            u8 idleActivityFlagsRest : 5;
        };
        s32 flameCommandPending; /* full-width flag: queued Flame command consumed by growl/circling handlers */
        f32 guardTimer; /* guard/flame state dwell timer: += / -= timeDelta against 150/60 thresholds (trickyGuard/trickyFlame) */
    };
    union {
        struct {
            f32 wanderTargetX; /* wander/return target position X that targetPosPtr is pointed at (&wanderTargetX); written from anim world/local posX plus a sin offset (tricky/tricky_substates) */
            f32 wanderTargetY; /* wander target position Y (written from anim world/local posY) */
            f32 wanderTargetZ; /* wander target position Z: anim world/local posZ plus a cos offset */
        };
        struct {
            GameObject* guardTarget; /* baddie object the guard is approaching (trickyGuard) */
            s32 guardWalkGroup;      /* walk group the guard post lies in (trickyGuard) */
            u8 guardCanSpawnHelpers; /* toggled by Flame while guarding; gates the helper-spawn branch (trickyGuard) */
        };
    };
    f32 sfxRepeatTimer; /* f32 countdown: -= timeDelta, on reaching floor fires an SFX and re-primes to gTrickyTimer600Frames (tricky_substates) */
    f32 moveHoldTimer; /* f32 countdown primed to randomGetRange(120,240) on entering idle move 0x29; counted down in move 0x2a and on reaching the floor advances to move 0x2b or 0x2c (tricky_substates) */
    f32 idleSfxTimer; /* f32 countdown: -= timeDelta, on reaching floor fires an idle vocalization SFX and re-primes to randomGetRange(500,750) (tricky/substates/weapone6) */
    f32 howlSparkleTimer; /* howl-call particle countdown; emits the 0x7F0 sparkle effect every 30 frames */
    TrickyCommand commands[MAX_COMM_PRESENT];
    u8 commandCount; /* number of queued Tricky commands (0..MAX_COMM_PRESENT); index into the command records at 0x748 (stride 8), bumped on enqueue / dropped on dequeue, used as the scan loop bound (tricky) */
    u8 pad799[0x79C - 0x799];
    f32 waterIdleTimer; /* countdown primed to TRICKY_WATER_COOLDOWN_FRAMES when water movement starts; Tricky_update clamps it toward zero, and idle behavior consumes a positive value to force TRICKY_ANIM_WATER_IDLE */
    f32 voiceCooldown; /* f32 countdown: -= timeDelta, clamped to floor; while > floor a TRICKY_VOICE line is (re)issued (tricky/trickyfollow/skeetla) */
    f32 sfxIntervalTimer; /* f32 countdown: -= timeDelta, on reaching zero fires an SFX and re-primes to a randomGetRange interval (skeetla 600..1200, weapone6 150..300) */
    GameObject* exclamationPromptChild;
    f32 exclamationPromptTimer;
    GameObject* questPromptChild;
    f32 questPromptTimer;
    GameObject* foodChild;
    TrickyPackedSlots
        packedSlots; /* 0x7BC: 2-bit anim-slot index per attached child (exclamationPromptChild/questPromptChild/foodChild) */
    u8 pad7BD[0x7C0 - 0x7BD];
    f32 foodVoiceTimer; /* child-object periodic phase timer: reset to gTrickyFloatZero when the child is attached, += timeDelta while it lives, wraps at gTrickyChildVoicePeriodFrames to (re)issue a TRICKY_VOICE line (tricky/substates/animobjd2) */
    f32 foodForceBlinkTimer; /* child-object periodic phase timer: += timeDelta, wraps at gTrickyTimer150Frames/gTrickyTimer600Frames to toggle the child's hidden anim flag */
    f32 foodBlinkTimer; /* child-object periodic phase timer: += timeDelta, wraps at gTrickyTimer30Frames, gates the child's hidden anim flag via gTrickyTimer20Frames */
    GameObject* spawnedChild;
    u8 pendingFollowRequest; /* TrickyPendingFollowRequest byte: 0 none, 1 queued follow-target handoff */
    u8 pad7D1[0x7D4 - 0x7D1];
    GameObject* pendingFollowObj; /* target object handed off to a sibling Tricky */
    f32 footPoints[4][3];
    f32 impressTimer; /* impress-move countdown: primed to gTrickyTimer20Frames by trickyImpress (which sets stateFlags 0x80000000); while that flag is set, -= timeDelta each cycle, and on reaching gTrickyFloatZero the flag is cleared and a TRICKY_VOICE line fires (tricky) */
    ObjAnimEventList
        animEvents; /* 0x808+4: root-motion deltas and triggered anim-event ids filled by ObjAnim_AdvanceCurrentMove; rootDelta* scale the sidestep/vertical/backstep moves, rootPitch drives the facing step, triggeredIds[] pick the bark sfx */
    f32 colorFadeTimer; /* color-variant crossfade countdown: primed to 20.0f, -= timeDelta; > 10 fades out, <= 10 swaps the texture selector and fades back in via timer/10 (tricky) */
    u8 colorVariant;    /* stats->ballReturnCount / 10; indexes the model's RGB channel-remap table */
    u8 pendingEnergy;   /* energy after feeding, committed by TRICKY_SEQUENCE_EVENT_STORE_ENERGY */
    union {
        u8 blendControlFlags; /* raw blend-channel control byte (bitfield view used by Tricky_updateBlendChannelWeight) */
        struct {
            u8 blendPending : 1; /* bit 7: requests priming of model blend channel 1 (Tricky_updateBlendChannelWeight consumes) */
            u8 blendActive : 1; /* bit 6: blend channel 1 ramp is running */
            u8 sequencePreserveBlend : 1;
            u8 blendControlFlagsRest : 5;
        };
    };
    u8 pad82F[0x830 - 0x82F];
    f32 blendWeight; /* model blend-channel 1 weight, ramped toward stats->energy/stats->maxEnergy and clamped to [0,1]; pushed to the channel as 2*weight-1 (tricky) */
    f32 blendVelocity; /* blendWeight ramp rate: += 0.004f*timeDelta toward the target, damped by 0.7f near it, zeroed at the clamp (tricky) */
    f32 particleTimer; /* f32 countdown decremented by timeDelta; while > threshold the queued particle effect keeps emitting; reset to a float sentinel on state entry (tricky/skeetla/weapone6/tricky_substates/mmp_cratercritter/animobjd2) */
} TrickyState;

STATIC_ASSERT(sizeof(TrickyState) == 0x83C);
STATIC_ASSERT(offsetof(TrickyState, speed) == 0x14);
STATIC_ASSERT(offsetof(TrickyState, moveVector.x) == 0x2C);
STATIC_ASSERT(offsetof(TrickyState, moveVector.z) == 0x30);
STATIC_ASSERT(sizeof(((TrickyState*)0)->moveVector) == 8);
STATIC_ASSERT(offsetof(TrickyState, animRate) == 0x34);
STATIC_ASSERT(offsetof(TrickyState, pendingAnimRate) == 0x38);
STATIC_ASSERT(offsetof(TrickyState, stateFlags) == 0x54);
STATIC_ASSERT(offsetof(TrickyState, guardPoint) == 0x71C);
STATIC_ASSERT(offsetof(TrickyState, guardTimer) == 0x728);
STATIC_ASSERT(offsetof(TrickyState, flameCommandPending) == 0x728);
STATIC_ASSERT(offsetof(TrickyState, followHeelTimer) == 0x71C);
STATIC_ASSERT(offsetof(TrickyState, playerContactTimer) == 0x720);
STATIC_ASSERT(offsetof(TrickyState, baddieBarkTimer) == 0x71C);
STATIC_ASSERT(offsetof(TrickyState, baddieAlertTarget) == 0x720);
STATIC_ASSERT(offsetof(TrickyState, flameEdgeNode) == 0x71C);
STATIC_ASSERT(offsetof(TrickyState, flameReturnNode) == 0x720);
STATIC_ASSERT(offsetof(TrickyState, flameTargetCallback) == 0x724);
STATIC_ASSERT(offsetof(TrickyState, baddieAlertWarp) == 0x724);
STATIC_ASSERT(offsetof(TrickyState, idleTimer) == 0x724);
STATIC_ASSERT(offsetof(TrickyState, guardTarget) == 0x72C);
STATIC_ASSERT(offsetof(TrickyState, sfxRepeatTimer) == 0x738);
STATIC_ASSERT(offsetof(TrickyState, cachedPatchGroups) == 0x98);
STATIC_ASSERT(offsetof(TrickyState, cachedPatchPositions) == 0xA0);
STATIC_ASSERT(offsetof(TrickyState, lastWalkGroup) == 0xD0);
STATIC_ASSERT(offsetof(TrickyState, linkedPatchGroup) == 0xD2);
STATIC_ASSERT(offsetof(TrickyState, linkedPatchPos) == 0xD4);
STATIC_ASSERT(offsetof(TrickyState, recoveryPos.x) == 0xE0);
STATIC_ASSERT(offsetof(TrickyState, recoveryPos.y) == 0xE4);
STATIC_ASSERT(offsetof(TrickyState, recoveryPos.z) == 0xE8);
STATIC_ASSERT(offsetof(TrickyState, patchExitPos) == 0xEC);
STATIC_ASSERT(offsetof(TrickyState, curvesCollision) == 0xF8);
STATIC_ASSERT(offsetof(TrickyState, curvesCollision.subtype) == 0x353);
STATIC_ASSERT(offsetof(TrickyState, curvesCollision.surfaceFlags) == 0x358);
STATIC_ASSERT(offsetof(TrickyState, curvesCollision.tiltPitch) == 0x290);
STATIC_ASSERT(offsetof(TrickyState, curvesCollision.tiltRoll) == 0x292);
STATIC_ASSERT(offsetof(TrickyState, curvesCollision.resultWaterDepth) == 0x2AC);
STATIC_ASSERT(offsetof(TrickyState, curvesCollision.resultFloorY) == 0x2B0);
STATIC_ASSERT(offsetof(TrickyState, curvesCollision.resultWaterY) == 0x2B4);
STATIC_ASSERT(offsetof(TrickyState, routeSeedNode) == 0x418);
STATIC_ASSERT(offsetof(TrickyState, routeSeedDirection) == 0x41C);
STATIC_ASSERT(offsetof(TrickyState, route) == 0x420);
STATIC_ASSERT(offsetof(TrickyState, route.reverse) == 0x4A0);
STATIC_ASSERT(offsetof(TrickyState, cachedRouteDef) == 0x528);
STATIC_ASSERT(offsetof(TrickyState, validatedRouteEntry) == 0x52C);
STATIC_ASSERT(offsetof(TrickyState, cachedWalkGroup) == 0x530);
STATIC_ASSERT(offsetof(TrickyState, walkGroup) == 0x532);
STATIC_ASSERT(offsetof(TrickyState, savedWalkGroup) == 0x534);
STATIC_ASSERT(offsetof(TrickyState, cachedRouteDirection) == 0x536);
STATIC_ASSERT(offsetof(TrickyState, pathSearches) == 0x538);
STATIC_ASSERT(offsetof(TrickyState, pathSearches[TRICKY_PATH_SEARCH_CACHE_INDEX]) == 0x6B8);
STATIC_ASSERT(offsetof(TrickyState, cachedRouteEntry) == 0x6E8);
STATIC_ASSERT(offsetof(TrickyState, cachedTargetWalkGroup) == 0x6EC);
STATIC_ASSERT(offsetof(TrickyState, playerObj) == 0x4);
STATIC_ASSERT(offsetof(TrickyState, stateIndex) == 0x8);
STATIC_ASSERT(offsetof(TrickyState, substate) == 0xA);
STATIC_ASSERT(offsetof(TrickyState, movementState) == 0x9);
STATIC_ASSERT(offsetof(TrickyState, sideCommandPromptMask) == 0xB);
STATIC_ASSERT(offsetof(TrickyState, wanderTargetX) == 0x72C);
STATIC_ASSERT(offsetof(TrickyState, lastContactObj) == 0x360);
STATIC_ASSERT(offsetof(TrickyState, hitType) == 0x368);
STATIC_ASSERT(offsetof(TrickyState, hitCooldown) == 0x370);
STATIC_ASSERT(offsetof(TrickyState, soundState) == 0x3A8);
STATIC_ASSERT(offsetof(TrickyState, soundState.mouthAngle) == 0x3BC);
STATIC_ASSERT(offsetof(TrickyState, pathPointPositions) == 0x3D8);
STATIC_ASSERT(offsetof(TrickyState, pathPointPositions[0].y) == 0x3DC);
STATIC_ASSERT(offsetof(TrickyState, pathPointPositions[0].z) == 0x3E0);
STATIC_ASSERT(offsetof(TrickyState, mouthPos) == 0x408);
STATIC_ASSERT(offsetof(TrickyState, mouthPos.y) == 0x40C);
STATIC_ASSERT(offsetof(TrickyState, mouthPos.z) == 0x410);
STATIC_ASSERT(offsetof(TrickyState, mouthYawOffset) == 0x414);
STATIC_ASSERT(offsetof(TrickyState, previousTargetPosPtr) == 0x6F0);
STATIC_ASSERT(offsetof(TrickyState, previousTargetPos.x) == 0x6F4);
STATIC_ASSERT(offsetof(TrickyState, previousTargetPos.y) == 0x6F8);
STATIC_ASSERT(offsetof(TrickyState, previousTargetPos.z) == 0x6FC);
STATIC_ASSERT(offsetof(TrickyState, flameChildren) == 0x700);
STATIC_ASSERT(sizeof(((TrickyState*)0)->flameChildren) == 0x1C);
STATIC_ASSERT(offsetof(TrickyState, fetchBallObj) == 0x700);
STATIC_ASSERT(offsetof(TrickyState, fetchCarryDelayTimer) == 0x704);
STATIC_ASSERT(offsetof(TrickyState, fetchThrowRetryTimer) == 0x708);
STATIC_ASSERT(offsetof(TrickyState, cannonballStartCurve) == 0x700);
STATIC_ASSERT(offsetof(TrickyState, cannonballRollSfxTimer) == 0x708);
STATIC_ASSERT(offsetof(TrickyState, cannonballRandomValue) == 0x710);
STATIC_ASSERT(offsetof(TrickyState, digTunnelStartNode) == 0x700);
STATIC_ASSERT(offsetof(TrickyState, digTunnelExitNode) == 0x704);
STATIC_ASSERT(offsetof(TrickyState, digTunnelEntryNode) == 0x708);
STATIC_ASSERT(offsetof(TrickyState, digTunnelWhineTimer) == 0x70C);
STATIC_ASSERT(offsetof(TrickyState, circlingDirection) == 0x700);
STATIC_ASSERT(offsetof(TrickyState, circlingAngle) == 0x704);
STATIC_ASSERT(offsetof(TrickyState, circlingAngleBits) == 0x704);
STATIC_ASSERT(offsetof(TrickyState, circlingTargetPos.x) == 0x708);
STATIC_ASSERT(offsetof(TrickyState, circlingTargetPos.y) == 0x70C);
STATIC_ASSERT(offsetof(TrickyState, circlingTargetPos.z) == 0x710);
STATIC_ASSERT(offsetof(TrickyState, tumbleweedPad701) == 0x701);
STATIC_ASSERT(offsetof(TrickyState, playerContactTimer) == 0x720);
STATIC_ASSERT(offsetof(TrickyState, baddieAlertTarget) == 0x720);
STATIC_ASSERT(offsetof(TrickyState, tumbleweedTargetX) == 0x704);
STATIC_ASSERT(offsetof(TrickyState, tumbleweedTargetY) == 0x708);
STATIC_ASSERT(offsetof(TrickyState, tumbleweedTargetZ) == 0x70C);
STATIC_ASSERT(offsetof(TrickyState, tumbleweedTargetObj) == 0x710);
STATIC_ASSERT(offsetof(TrickyState, secretDigPressTimer) == 0x700);
STATIC_ASSERT(offsetof(TrickyState, secretDigOriginX) == 0x704);
STATIC_ASSERT(offsetof(TrickyState, secretDigOriginZ) == 0x708);
STATIC_ASSERT(offsetof(TrickyState, secretDigCurve) == 0x70C);
STATIC_ASSERT(offsetof(TrickyState, secretDigWhineTimer) == 0x710);
STATIC_ASSERT(offsetof(TrickyState, statusFlags) == 0x58);
STATIC_ASSERT(offsetof(TrickyState, stateFlags) == 0x54);
STATIC_ASSERT(sizeof(((TrickyState*)0)->stateFlags) == 4);
STATIC_ASSERT(offsetof(TrickyState, targetYaw) == 0x5A);
STATIC_ASSERT(offsetof(TrickyState, howlSparkleTimer) == 0x744);
STATIC_ASSERT(offsetof(TrickyState, commands) == 0x748);
STATIC_ASSERT(offsetof(TrickyState, commandCount) == 0x798);
STATIC_ASSERT(offsetof(TrickyState, exclamationPromptChild) == 0x7A8);
STATIC_ASSERT(offsetof(TrickyState, exclamationPromptTimer) == 0x7AC);
STATIC_ASSERT(offsetof(TrickyState, questPromptChild) == 0x7B0);
STATIC_ASSERT(offsetof(TrickyState, questPromptTimer) == 0x7B4);
STATIC_ASSERT(offsetof(TrickyState, foodChild) == 0x7B8);
STATIC_ASSERT(offsetof(TrickyState, packedSlots) == 0x7BC);
STATIC_ASSERT(offsetof(TrickyState, footPoints) == 0x7D8);
STATIC_ASSERT(offsetof(TrickyState, impressTimer) == 0x808);
STATIC_ASSERT(offsetof(TrickyState, animEvents) == 0x80C);
STATIC_ASSERT(offsetof(TrickyState, colorFadeTimer) == 0x828);
STATIC_ASSERT(offsetof(TrickyState, blendControlFlags) == 0x82E);
STATIC_ASSERT(offsetof(TrickyState, blendWeight) == 0x830);
STATIC_ASSERT(offsetof(TrickyState, blendVelocity) == 0x834);
STATIC_ASSERT(offsetof(TrickyState, particleTimer) == 0x838);

#endif /* MAIN_DLL_TRICKY_STATE_H_ */
