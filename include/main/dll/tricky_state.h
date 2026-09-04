#ifndef MAIN_DLL_TRICKY_STATE_H_
#define MAIN_DLL_TRICKY_STATE_H_

#include "types.h"
#include "global.h"
#include "main/objprint_character_api.h"
#include "main/dll/curve_walker.h"
#include "main/dll/curves_collision_state.h"
#include "game/objects/object.h"
#include "main/objprint_sound_api.h"
#include "main/pi_dolphin_path_api.h"
#include "main/mapEventTypes.h"

/* Shared TrickyState.stateFlags bits used across the Tricky sidekick / spawned
 * sibling handlers (tricky, tricky_substates, trickyfollow, tumbleweedbush,
 * weaponE6). */
#define TRICKY_STATE_FLAG_CHILDREN_ACTIVE  0x800  /* spawned child objects are active */
#define TRICKY_STATE_FLAG_CHILDREN_CLEANUP 0x1000 /* child objects torn down this cycle */
#define TRICKY_STATE_FLAG_MOVE_ADVANCING                                                                               \
    0x8000000 /* ObjAnim_AdvanceCurrentMove reported the current move still advancing */
#define TRICKY_STATE_FLAG_PATH_PATCHES_VALID 0x400 /* patch[] and patchTargets[] describe targetPosPtr */
#define TRICKY_STATE_FLAG_COMMAND_ACTIVE     0x10u /* sidekick command/flame/dig/guard action is active */
#define TRICKY_STATE_FLAG_RECALL_REQUEST     0x10000u
#define TRICKY_STATE_FLAG_HEEL_REQUEST       0x20000u
#define TRICKY_STATE_FLAG_GUARD_REQUEST      0x40000u

/* TrickyState.movementState - the walk/jump phase selector switched on in
 * trickyUpdateMovementState. The names are the ones the retail debug build
 * printed for each case ("walk wait", "walk free", "walk start patch",
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

typedef union TrickyScratch {
    GameObject* obj;
    struct RomCurveDef* curve;
    void* ptr;
    s32 i;
    u32 u;
    f32 f;
    struct {
        u8 hi : 4; /* tricky NW-mammoth tumbleweed-count latch (top nibble of the scratch word) */
        u8 lo : 4;
    } nib;
} TrickyScratch;

typedef int (*TrickyActionCallback)(GameObject* obj, int amount);

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
    u8 ttlFrames;
    u8 pad7;
} TrickyCommand;

typedef struct TrickyJumpArc {
    f32 duration;  /* 0x00: horizontal distance / Tricky follow vertical divisor */
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
 * Field widths mirror the deref widths observed across Tricky, Skeetla, and
 * companion command handlers; unobserved ranges are padded.
 * Tricky_getExtraSize returns 0x83C, including the final particle timer.
 */
typedef struct TrickyState {
    TrickyStats* stats;    /* persisted energy and ball-play statistics */
    GameObject* playerObj; /* owning player/sidekick object */
    u8 stateIndex; /* primary Tricky state selector (0..0x11); indexes the handlerBase[] per-state handler dispatch table and gates the state machine */
    u8 movementState;         /* TRICKY_MOVE_* path/jump phase selector */
    u8 substate;              /* per-state handler substate */
    u8 sideCommandPromptMask; /* transient sidekick command prompt bitmask:
                                 |= TRICKY_COMMAND_TYPE_TO_FLAG(commandType) when another object enables a command,
                                 OR'd with Call+Stay into the UI prompt mask, tested != 0, cleared to 0 (tricky) */
    u8 pad0C;
    s8 commandPhase; /* current command-dispatch phase selector (-1 idle, 1..5 active); compared == 3 / != 0 to gate the queued-command state machine (tricky/substates/weapone6/tumbleweedbush/mmp) */
    u8 padE[0x10 - 0xE];
    f32 prevSpeed;
    f32 speed; /* planar speed magnitude, multiplied into dirX/dirZ */
    f32 animTransitionTimer;
    u8 pad1C[0x20 - 0x1C];
    int moveId;            /* compared to anim.currentMove, passed to ObjAnim_SetCurrentMove */
    GameObject* followObj; /* the followed object (playerObj/target/found stores; dll vtable dispatched) */
    f32* targetPosPtr;     /* current target/path position (compared to previousPathPoint; fed to pathSearchBegin) */
    f32 dirX;              /* normalized planar direction (pos delta / length) */
    f32 dirZ;
    f32 moveProgress; /* passed to ObjAnim_SetMoveProgress */
    f32 moveProgressTarget;
    f32 arcMoveProgress; /* normalized jump-arc/tween progress (arc->time / arc->duration, clamped/eased); passed to ObjAnim_SetMoveProgress (trickyfollow sets, tricky reads) */
    f32 sidestepDelta;
    f32 backstepDelta;
    f32 verticalDelta;
    f32 rotStepScale;
    u32 pendingStateFlags;
    u32 stateFlags; /* the TRICKY state flag word (bit masks 0x80..0x100000) */
    union {
        struct {
            u8 statusFlags;
            u8 pad59[0x5A - 0x59];
            s16 targetYaw; /* target facing angle: set from targetYaw (skeetla); tricky interpolates anim.rotX toward it (diff = targetYaw - rotX) under TRICKY_STATE_FLAG_ROTATE */
        };
        struct {
            u8 ownsWarpHelperObject : 1;
            u8 soundSuppressed : 1; /* statusFlags bit 6: suppresses barks/voice sfx (trickySetSoundSuppressed / trickyTryPlaySound) */
            u8 heightTracking : 1; /* statusFlags bit 5 */
            u8 statusFlagsLow : 5;
        };
        struct {
            u32 warpCooldownHi : 3;
            u32 warpCooldown : 4; /* packed trickywarp cooldown counter (trickyShouldGoToWarpPoint) */
            u32 warpCooldownLo : 1;
        };
    };
    s32 heightTrackObjId; /* object ident being height-tracked; -1 while searching for a nearby XYZ animator */
    f32 trackedHeight;
    TrickyJumpArc jumpArc; /* 0x64: ballistic hop arc */
    u8 pad84[0x8C - 0x84];
    f32 prevLocalPosX;
    f32 prevLocalPosY;
    f32 prevLocalPosZ;
    s16 patch[4]; /* curve-walk patch values (dll_DF trickyUpdateMovementState) */
    Vec patchTargets[4];
    u16 activeWalkGroup; /* current active walk-group id (getPatchGroup/walkGroupFn arg; tracked vs targetWg) */
    s16 linkedWalkGroup; /* walk-group/patch id linked to activeWalkGroup: set to the intersected walk-group product, compared == targetWg/getPatchGroup results, cleared to 0 (trickyfollow/tricky_substates) */
    Vec linkedPatchPos;
    f32 homePosX; /* home position, init from obj world pos */
    f32 homePosY;
    f32 homePosZ;
    Vec patchExitPos;
    union {
        CurvesCollisionState curvesCollision; /* DLL 21 owns the collision record at 0xF8..0x360. */
        struct {
            /* Legacy actor-helper views of the same storage. */
            u8 padF8[0x1B8 - 0xF8];
            f32 nearestSpecialDeltaY; /* signed dy to the nearest special-surface (type 0xe) floor hit */
            u8 pad1BC[0x25F - 0x1BC];
            s8 physicsActive; /* same actor-record slot as BaddieState.physicsActive (free-fall physics enable) */
            u8 pad260;
            u8 bboxTraceFlags; /* same actor-record slot as BaddieState.bboxTraceFlags */
            u8 pad262[0x264 - 0x262];
            u8 surfaceFlags; /* TRICKY_SURFACE_FLAG_* (HAS_NEARBY_FLOOR etc.) */
            u8 pad265[0x29C - 0x265];
            GameObject* actionTargetObj;
            u16 turnOctant; /* (u16 angleDelta >> 13): which 1/8 sector the turn falls in; used as an anim mode */
            u16 turnAngleDelta; /* signed angle to actionTargetObj minus world rotZ, normalized to +/-0x8000; feeds turnOctant (>>13) */
            u16 targetDist;        /* distance to actionTargetObj: (s16)sqrt(dx^2+dy^2+dz^2) */
            u16 targetHeightDelta; /* (s16)(actionTargetObj.worldPosY - self.worldPosY): vertical offset to target */
            u8 pad2A8[0x2B8 - 0x2A8];
            f32 lookDirX; /* look/aim direction: yaw = getAngle(-X,-Z), pitch = getAngle(Y, hyp(X,Z)) */
            f32 lookDirY;
            f32 lookDirZ;
            u8 pad2C4[0x2D0 - 0x2C4];
            f32 freezeEffectTimer; /* counts down by timeDelta while frozen; resets when the shatter effect fires */
            f32 repeatHitCooldown; /* shared EnemyState repeat-hit guard slot */
            f32 freezeRecoverTimer;
            u32 controlFlags;     /* shared EnemyState actor-control slot at 0x2DC */
            u32 prevControlFlags; /* controlFlags snapshot, tested for newly-raised control bits in the shared actor code */
            u32 flags2E4;         /* shared EnemyState flags2E4 slot */
            u32 flags2E8;         /* control/state flag word (bits 1/4/0x10/0x20/0x200/0x208) */
            u16 hitStunFrames; /* shared EnemyState hit-reaction duration slot */
            u8 pad2EE[0x2EF - 0x2EE];
            u8 actionId;     /* current action/move selector (0..5); compared against prevActionId to detect change */
            u8 prevActionId; /* previous frame's actionId */
            u8 flags2F1;     /* decoded player-attack flags; shared with EnemyState hit/freeze handling */
            u8 pad2F2[0x2F5 - 0x2F2];
            u8 spawnBits;             /* reward-drop selector decoded from the player attack flags */
            u8 frozenFadeCounter : 5; /* countdown gating the frozen-shatter fade-in sfx */
            u8 unusedFrozenFadeBits : 3;
            u8 pad2F7[0x2F8 - 0x2F7];
            u16 animEventMask; /* per-frame bitmask OR'd from (1 << anim event index); fed to objAudioFn */
            u8 pad2FA[0x300 - 0x2FA];
            f32 gravity; /* fall acceleration: velocityY -= gravity*dt, posY -= K*gravity*dt^2 */
            f32 base;
            f32 animPlaySpeed;
            f32 currentMoveProgress;
            f32 pathSpeed;       /* shared actor path-speed slot (EnemyState.pathSpeed); not read by Tricky */
            f32 moveSpeedScale0; /* animPlaySpeed = K / (K2 * scale) for moveId0 */
            f32 moveSpeedScale1; /* paired with moveId1 */
            f32 moveSpeedScale2; /* paired with moveId2 */
            u8 moveId0;          /* ObjAnim_SetCurrentMove move id */
            u8 moveId1;
            u8 moveId2;
            u8 rootMotionFlags; /* shared actor root-motion bit flags (0x1/0x2/0x4/0x8), same slot as EnemyState.rootMotionFlags */
            u8 pad324[0x353 - 0x324];
            u8 heightUpdateActive; /* set 1 at update-cycle start; cleared to 0 when the object leaves its map block or a ground-snap fires; while (s8)set the water-level / tracked-height float update runs, else velocityY is zeroed (tricky sets, trickyfollow/skeetla clear+read) */
            u8 pad354[0x358 - 0x354];
            s8 sideCommandHitFlags; /* bit-flag byte decomposed for the "sidecommand hits" debug print */
            u8 pad359[0x360 - 0x359];
        };
    };
    void* lastContactObj;
    f32 contactTimer;
    int light;      /* object link */
    int modelChain; /* ObjModelChain handle toggled via ObjModelChain_SetEnabled */
    f32 hitCooldown;
    u8 groundSnapCounter; /* frame countdown that forces the ground-snap path: != 0 -> decrement and do the height snap; primed to 2 on state entry (tricky/skeetla) */
    u8 pad375[0x378 - 0x375];
    CharacterEyeAnimState
        eyeAnimState; /* 0x378: head-aim / eye-blink record; lookAtPos is followObj's captured world position */
    u8 pad3A0[0x3A8 - 0x3A0];
    ObjSoundState soundState; /* 0x3A8: object-channel sound playback state */
    union {
        struct {
            f32 sparkPos0X; /* spark particle emit point 0 (skeetla_spawnLinkedSparks args.xyz) */
            f32 sparkPos0Y;
            f32 sparkPos0Z;
            f32 sparkPos1X; /* spark particle emit point 1 */
            f32 sparkPos1Y;
            f32 sparkPos1Z;
            u8 pad3F0[0x408 - 0x3F0];
        };
        Vec pathPointPositions[4]; /* ObjPath points 4..7 refreshed by Tricky_render */
    };
    f32 renderPosX; /* copied to a child object's localPos during Tricky_render */
    f32 renderPosY;
    f32 renderPosZ;
    s16 modelAnchorRotY;
    u8 pad416[0x418 - 0x416];
    struct RomCurveDef* routeSeedNode; /* candidate route node chosen before seeding route */
    u8 routeSeedDir;
    u8 pad41D[0x420 - 0x41D];
    RomCurveWalker route;
    RomCurveDef*
        cachedRouteDef; /* route-select memo key: the routeDef the memo was resolved for, compared == routeDef then re-stored; when it + cachedWalkGroup + cachedRouteFlags all match, validatedRouteEntry is reused (skeetla) */
    RomCurveDef* validatedRouteEntry; /* route entry pointer validated via skeetla_validateRouteEntry (skeetla) */
    u16 cachedWalkGroup; /* route-select memo key: the walkGroup value that validatedRouteEntry was resolved for; compared == walkGroup (alongside cachedRouteDef/cachedRouteFlags) to reuse the cached entry, re-stored = walkGroup on a memo miss (skeetla); also gates the follow-slot walk-group update (trickyfollow) */
    u16 walkGroup;       /* current walk-group id (route/path selection; compared to targetWg and node group bytes) */
    u16 savedWalkGroup;  /* mirrored from walkGroup (dll_DF); retained group used to gate route re-seeding */
    u8 cachedRouteFlags; /* cached (routeFlagValue & 0xff): route-select memo key stored alongside cachedRouteDef; compared == (routeFlagValue & 0xff) to reuse validatedRouteEntry (skeetla) */
    u8 pad537[1];
    PathSearch pathSearches[9]; /* route-search workspaces, 0x538..0x6E8 */
    union {
        RomCurveDef*
            cachedRouteEntry; /* path-search start/next-point cache slot, validated via skeetla_validateRouteEntry */
        u32 cachedRouteId;    /* raw view of cachedRouteEntry retained for consumers still recovered as word keys */
    };
    int cachedPathId; /* pathId the cachedRouteEntry was resolved for */
    f32* previousPathPoint;
    f32 previousPathX;
    f32 previousPathY;
    f32 previousPathZ;
    union {
        struct {
            TrickyScratch scratch700;
            TrickyScratch scratch704;
            TrickyScratch scratch708;
            TrickyScratch scratch70C;
            TrickyScratch scratch710;
            u8 pad714[0x71C - 0x714];
        };
        struct {
            GameObject* fetchBallObj; /* sidekick ball object being fetched/returned */
            f32 fetchCarryDelayTimer;
            f32 fetchThrowRetryTimer;
            TrickyScratch fetchScratch70C;
            TrickyScratch fetchScratch710;
            u8 fetchPad714[0x71C - 0x714];
        };
        struct {
            struct RomCurveDef* cannonballStartCurve;
            TrickyScratch cannonballScratch704;
            f32 cannonballRollSfxTimer;
            TrickyScratch cannonballScratch70C;
            TrickyScratch cannonballScratch710;
            u8 cannonballPad714[0x71C - 0x714];
        };
        struct {
            TrickyScratch digTunnelStartNode;
            TrickyScratch digTunnelExitNode;
            TrickyScratch digTunnelEntryNode;
            TrickyScratch digTunnelWhineTimer;
            TrickyScratch digTunnelScratch710;
            u8 digTunnelPad714[0x71C - 0x714];
        };
        struct {
            TrickyScratch circlingDirection;
            TrickyScratch circlingAngle;
            TrickyScratch circlingTargetX;
            TrickyScratch circlingTargetY;
            TrickyScratch circlingTargetZ;
            u8 circlingPad714[0x71C - 0x714];
        };
        struct {
            TrickyScratch tumbleweedCountLatch;
            f32 tumbleweedTargetX;
            f32 tumbleweedTargetY;
            f32 tumbleweedTargetZ;
            GameObject* tumbleweedTargetObj;
            u8 tumbleweedPad714[0x71C - 0x714];
        };
        struct {
            f32 secretDigPressTimer;
            f32 secretDigOriginX;
            f32 secretDigOriginZ;
            struct RomCurveDef* secretDigCurve;
            f32 secretDigWhineTimer;
            u8 secretDigPad714[0x71C - 0x714];
        };
        GameObject* flameChildren[7]; /* flame/dig helpers spawned and retired as one seven-object group */
    };
    union {
        struct {
            f32 cooldownA; /* f32 countdown: -= timeDelta, clamped to gTrickyFloatZero; == floor gates a state/anim transition (tricky/substates/weapone6/tumbleweedbush/mmp) */
            TrickyScratch
                cooldownB; /* .f: countdown paired with cooldownA: -= timeDelta, clamped to floor; == floor gates a move, > floor gates fidget/contact-sfx (tricky/substates/weapone6/tumbleweedbush). .ptr: reused in the animobjd2 orbit substate to hold the circling-target object, copied into followObj */
            union {
                GameObject* circlingWarpDetour; /* active trickywarp detour while orbiting a circling target */
                f32 idleTimer;
                TrickyActionCallback actionCallback;
            };
        };
        f32 guardPoint
            [3]; /* trickyGuard: guard-post position (home pos - 15 units along facing); trickyFlame clears [0]/[1] with 0.0f on exit */
        struct {
            struct RomCurveDef* flameEdgeNode;   /* trickyFlame: Objfsa_FindNearestCurveType24 result */
            struct RomCurveDef* flameReturnNode; /* trickyFlame: getById(flameEdgeNode->linkIds[0]) */
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
STATIC_ASSERT(offsetof(TrickyState, stateFlags) == 0x54);
STATIC_ASSERT(offsetof(TrickyState, guardPoint) == 0x71C);
STATIC_ASSERT(offsetof(TrickyState, guardTimer) == 0x728);
STATIC_ASSERT(offsetof(TrickyState, flameCommandPending) == 0x728);
STATIC_ASSERT(offsetof(TrickyState, actionCallback) == 0x724);
STATIC_ASSERT(offsetof(TrickyState, circlingWarpDetour) == 0x724);
STATIC_ASSERT(offsetof(TrickyState, idleTimer) == 0x724);
STATIC_ASSERT(offsetof(TrickyState, guardTarget) == 0x72C);
STATIC_ASSERT(offsetof(TrickyState, sfxRepeatTimer) == 0x738);
STATIC_ASSERT(offsetof(TrickyState, patchTargets) == 0xA0);
STATIC_ASSERT(offsetof(TrickyState, linkedPatchPos) == 0xD4);
STATIC_ASSERT(offsetof(TrickyState, patchExitPos) == 0xEC);
STATIC_ASSERT(offsetof(TrickyState, curvesCollision) == 0xF8);
STATIC_ASSERT(offsetof(TrickyState, curvesCollision.tiltPitch) == 0x290);
STATIC_ASSERT(offsetof(TrickyState, curvesCollision.tiltRoll) == 0x292);
STATIC_ASSERT(offsetof(TrickyState, curvesCollision.resultWaterDepth) == 0x2AC);
STATIC_ASSERT(offsetof(TrickyState, curvesCollision.resultFloorY) == 0x2B0);
STATIC_ASSERT(offsetof(TrickyState, curvesCollision.resultWaterY) == 0x2B4);
STATIC_ASSERT(offsetof(TrickyState, routeSeedNode) == 0x418);
STATIC_ASSERT(offsetof(TrickyState, route) == 0x420);
STATIC_ASSERT(offsetof(TrickyState, route.reverse) == 0x4A0);
STATIC_ASSERT(offsetof(TrickyState, pathSearches) == 0x538);
STATIC_ASSERT(offsetof(TrickyState, pathSearches[8]) == 0x6B8);
STATIC_ASSERT(offsetof(TrickyState, playerObj) == 0x4);
STATIC_ASSERT(offsetof(TrickyState, stateIndex) == 0x8);
STATIC_ASSERT(offsetof(TrickyState, substate) == 0xA);
STATIC_ASSERT(offsetof(TrickyState, movementState) == 0x9);
STATIC_ASSERT(offsetof(TrickyState, sideCommandPromptMask) == 0xB);
STATIC_ASSERT(offsetof(TrickyState, wanderTargetX) == 0x72C);
STATIC_ASSERT(offsetof(TrickyState, lastContactObj) == 0x360);
STATIC_ASSERT(offsetof(TrickyState, hitCooldown) == 0x370);
STATIC_ASSERT(offsetof(TrickyState, soundState) == 0x3A8);
STATIC_ASSERT(offsetof(TrickyState, pathPointPositions) == 0x3D8);
STATIC_ASSERT(offsetof(TrickyState, pathPointPositions[0].y) == 0x3DC);
STATIC_ASSERT(offsetof(TrickyState, pathPointPositions[0].z) == 0x3E0);
STATIC_ASSERT(offsetof(TrickyState, physicsActive) == 0x25F);
STATIC_ASSERT(offsetof(TrickyState, bboxTraceFlags) == 0x261);
STATIC_ASSERT(offsetof(TrickyState, freezeEffectTimer) == 0x2D0);
STATIC_ASSERT(offsetof(TrickyState, repeatHitCooldown) == 0x2D4);
STATIC_ASSERT(offsetof(TrickyState, freezeRecoverTimer) == 0x2D8);
STATIC_ASSERT(offsetof(TrickyState, controlFlags) == 0x2DC);
STATIC_ASSERT(offsetof(TrickyState, prevControlFlags) == 0x2E0);
STATIC_ASSERT(offsetof(TrickyState, flags2E4) == 0x2E4);
STATIC_ASSERT(offsetof(TrickyState, flags2E8) == 0x2E8);
STATIC_ASSERT(offsetof(TrickyState, hitStunFrames) == 0x2EC);
STATIC_ASSERT(offsetof(TrickyState, flags2F1) == 0x2F1);
STATIC_ASSERT(offsetof(TrickyState, spawnBits) == 0x2F5);
STATIC_ASSERT(offsetof(TrickyState, pathSpeed) == 0x310);
STATIC_ASSERT(offsetof(TrickyState, rootMotionFlags) == 0x323);
STATIC_ASSERT(offsetof(TrickyState, previousPathPoint) == 0x6F0);
STATIC_ASSERT(offsetof(TrickyState, flameChildren) == 0x700);
STATIC_ASSERT(offsetof(TrickyState, scratch704) == 0x704);
STATIC_ASSERT(offsetof(TrickyState, fetchBallObj) == 0x700);
STATIC_ASSERT(offsetof(TrickyState, fetchCarryDelayTimer) == 0x704);
STATIC_ASSERT(offsetof(TrickyState, fetchThrowRetryTimer) == 0x708);
STATIC_ASSERT(offsetof(TrickyState, cannonballStartCurve) == 0x700);
STATIC_ASSERT(offsetof(TrickyState, cannonballRollSfxTimer) == 0x708);
STATIC_ASSERT(offsetof(TrickyState, digTunnelStartNode) == 0x700);
STATIC_ASSERT(offsetof(TrickyState, digTunnelExitNode) == 0x704);
STATIC_ASSERT(offsetof(TrickyState, digTunnelEntryNode) == 0x708);
STATIC_ASSERT(offsetof(TrickyState, digTunnelWhineTimer) == 0x70C);
STATIC_ASSERT(offsetof(TrickyState, circlingDirection) == 0x700);
STATIC_ASSERT(offsetof(TrickyState, circlingAngle) == 0x704);
STATIC_ASSERT(offsetof(TrickyState, circlingTargetX) == 0x708);
STATIC_ASSERT(offsetof(TrickyState, circlingTargetY) == 0x70C);
STATIC_ASSERT(offsetof(TrickyState, circlingTargetZ) == 0x710);
STATIC_ASSERT(offsetof(TrickyState, tumbleweedCountLatch) == 0x700);
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
