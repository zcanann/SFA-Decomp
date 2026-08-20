#ifndef MAIN_DLL_BADDIE_STATE_H_
#define MAIN_DLL_BADDIE_STATE_H_

#include "game/objects/object_setup.h"
#include "types.h"
#include "global.h"
#include "main/objprint_character_api.h"
#include "main/voxmaps.h"
#include "main/dll/curves_collision_state.h"

struct GameObject;
struct BaddieState;
typedef void (*BaddieStateExitFn)(struct GameObject* obj, struct BaddieState* state);

/*
 * BaddieState - the engine-wide actor-control record that lives at the
 * head of the obj+0xB8 extra block for objects driven through
 * gBaddieControlInterface / gPlayerInterface (the name follows the
 * gBaddieControlInterface linkage; ActorControlState was the considered
 * alternative since the player shares it - cheap to rename later).
 *
 * Shared layout evidence:
 * - scarab.c (dll_CA/CB/CE: extraSizes 0x458/0x41c/0x410 - this struct is
 *   the common 0x410 prefix; nothing past 0x40C is referenced there) and
 *   slot 202's iceBaddie implementation.
 * - player.c's "inner" is the SAME record (0x274 mode compares, 0x27A
 *   just-started flag, 0x346 latch, ...).
 * - dll_000F (engine/15) is the shared move/substate controller and is the
 *   only writer of most of the head.
 * - treasurechest.c / dlls/objects/437/437.c reference the same offsets.
 * - DR_CloudRunner's 0xBC8 extra block EMBEDS this record as its prefix
 *   (0x25F/0x28C/0x314/0x354 head + private tail from ~0x410).
 *
 * NOT evidence for this struct: the generic enemy DLL 0xC9 (slot 201 plus its
 * family handlers in slot 202). Its obj+0xB8 record is EnemyState
 * (dll_00C9_enemy.h, enemy_getExtraSize() = 0x370). The two records agree on
 * the engine-controlled head but diverge from roughly 0x25F up - 0x2B0 is
 * BaddieState scratch but EnemyState's health numerator, 0x2D0 is a target
 * pointer here and a countdown timer there, and 0x2F4-0x322 holds an unrelated
 * field set in each. Never read one through the other's names.
 *
 * Only fields with read/write evidence in the DLLs listed above are named;
 * everything else is padded.
 */
typedef struct BaddieState {
    int flags0; /* actor-state flags; player climbing sets bit 0x200000 */
    /*
     * 0x004..0x26C is a CurvesCollisionState. The collision engine (DLL 21)
     * writes the region through the curves names; the player and the baddies
     * read it back through the padded view below. Two independent paddings over
     * one set of bytes is exactly how the two descriptions drift apart, so the
     * union states the aliasing instead of leaving it to be rediscovered.
     */
    union {
        CurvesCollisionState curvesCollision;
        struct {
    int flags4; /* secondary actor-state flags; player climbing sets bits 0x100000/0x8000000 */
    u8 unk08[0x14 - 0x8];
    f32 posX; /* copied into spawned contact objects as position */
    f32 posY;
    f32 posZ;
    u8 unk20[0x38 - 0x20];
    f32 velX; /* copied into spawned contact objects as velocity */
    f32 velY;
    f32 velZ;
    u8 unk44[0xB8 - 0x44];
    s8 surfaceSoundIndex; /* 0..0x22 index into the per-type contact-sfx tables (objAudioDispatchAnimEvents) */
    u8 padB9[0xBC - 0xB9];
    u8 paletteSlot; /* indexes the palette table (paletteIndex = gIceBaddiePaletteIndexTable[slot]) */
    u8 unkBD[0xC4 - 0xBD];
    void *contactObj; /* GameObject*; its anim.romDefNo (0x5d/0x99/0x1db/0x223) switches a sfx override (intersect.c) */
    u8 unkC8[0x118 - 0xC8];
    f32 unk118; /* a local-space point carried through a reparent exactly like
        anim.localPos: player.c playerReparentPreservingWorldTransform pushes it to world space through the old
        parent and pulls it back through the new one. No other reader in the tree. */
    f32 unk11C;
    f32 unk120;
    u8 unk124[0x19C - 0x124];
    s16 spawnRotY; /* pair copied into the spawn-setup shorts; restored into anim.rotY */
    s16 spawnRotZ; /* restored into anim.rotZ */
    u8 unk1A0[0x1B0 - 0x1A0];
    f32 unk1B0; /* player.c compares it against 15 / 40 / 120 to gate landing and
        state-exit branches */
    f32 waterDepth; /* compared > threshold to fire the waterfx splash path (intersect.c) */
    u8 unk1B8[0x1C0 - 0x1B8];
    f32 waterSurfaceY; /* world-Y of the water surface under the actor, or the
        no-water sentinel; player.c copies it into PlayerState.waterSurfaceY and
        derives the submerged depth from it */
    u8 unk1C4[0x25B - 0x1C4];
    s8 contactSfxMuted; /* nonzero suppresses contact sfx unless contactSfxFlags bit 0x10 (intersect.c) */
    u8 unk25C[0x25F - 0x25C];
    s8 physicsActive; /* enables the free-fall physics path: gravity integration (velY -= g*dt), floor bounce response; set when thrown/spat */
    s8 contactSfxFlags; /* bit 0x10 allows contact sfx while contactSfxMuted is set (intersect.c) */
    u8 bboxTraceFlags; /* bbox trace filter handed to trackGetLineIntersect */
    u8 groundContact; /* nonzero while the actor is resting on a surface this frame; the shared controller and player.c re-derive velocity from the position delta when it or surfaceFlags bit 2 is set */
    u8 unk263;
/* surfaceFlags bit: a floor was found within the ground-probe distance. Set and
 * cleared by the shared floor scan in dll_00C9 (Baddie.c), consumed by the
 * riders/controllers to enable ground handling. */
#define BADDIE_SURFACE_HAS_NEARBY_FLOOR 0x10
    s8 surfaceFlags; /* per-frame ground/surface contact flags, same field the dll_00C9 enemy view calls surfaceFlags; bits 0x1/0x2/0x10/0x20 are ground-contact channels (mask 0x33 = "touching ground at all") */
    u8 unk265[0x26C - 0x265];
        };
    };
    s16 unk26C; /* the shared player-interface init writes its two mode arguments here */
    s16 unk26E;
    s16 substate; /* CA-family substate 0..5; gates the map-event re-register when != 3 */
    s16 prevSubstate; /* latched from substate for change detection (prevSubstate = startState in objseq) */
    s16 controlMode; /* current control move/mode; gPlayerInterface[5](obj,state,N) requests N */
    s16 prevControlMode; /* latched from controlMode for change detection (parallels prevSubstate/substate): controlMode != prevControlMode arms moveJustStartedA, then prevControlMode = controlMode; consumers compare it to prior mode ids (dll_000F/icebaddie/player) */
    s16 stateId; /* active player/control state id, written when a state handler starts */
    s8 moveJustStartedA; /* one-shot, tested at SeqFn entry */
    s8 moveJustStartedB; /* one-shot, secondary channel (death/cleanup handlers) */
    void* orientationAxesOut; /* 0x27C: optional destination for the actor's world
        orientation axes. When non-NULL the shared controller writes three unit
        vectors there each update - +Z at +0x00, +Y at +0x0C, +X at +0x18 - by
        transforming the unit axes through the object's rotation matrix. player.c
        points it at PlayerState.orientationAxes. */
    f32 animSpeedA; /* anim blend speed pair */
    f32 animSpeedB;
    f32 animSpeedY; /* vertical companion of animSpeedA/animSpeedB: dll_000F feeds the triple to Matrix_TransformPoint as (animSpeedB, animSpeedY, -animSpeedA), i.e. local (x,y,z), and only when flags0 bit 0x10000 is set - the bit player_advanceMove raises when the move's root motion drives Y */
    f32 moveInputZ;
    f32 moveInputX;
    f32 animSpeedC; /* third of the animSpeed family - stored in lockstep with animSpeedB (z = K; animSpeedC = z; animSpeedB = z), scaled with animSpeedA and obj+0x28 */
    f32 inputMagnitude;
    union {
        void* trackedObj; /* current target/player object */
        f32 previousInputMagnitude;
    };
    f32 moveSpeed; /* per-mode movement speed */
    f32 gravity; /* fall acceleration: velocityY -= gravity * timeDelta (dll_000F player_applyGravity) */
    /* 0x2A8/0x2AC are two independent 0..1 ramp progresses for the deferred
     * "nudge" the shared controller applies over several frames. dll_000F
     * player_render2 steps 0x2A8 by f1*f2, clamps it at 1.0 and adds
     * nudgeYaw * (that frame's increment) straight into anim.rotX;
     * player_modelMtxFn steps 0x2AC the same way and adds
     * nudgePos{X,Y,Z} * increment into the model matrix translation. */
    f32 nudgeYawProgress;
    f32 nudgePosProgress;
    u8 pad2B0[0x2B4 - 0x2B0];
    f32 rootMotionDelta; /* raw per-frame root-motion component for the axis the move selects, stored undivided when the caller asks for displacement rather than velocity (dll_000F player_advanceMove, flags bit 0x10); the consumer scales it by timeDelta itself */
    f32 velSmoothTime; /* first-order velocity smoothing divisor: vel += t * (target - vel) / velSmoothTime */
    f32 moveTargetDistance; /* planar distance to the current move destination or curve point (dll_000F player_moveTowardPoint / player_followCurve); below it the input is damped, and player_updateCurve zeroes it when there is no curve */
    f32 targetDistance; /* sqrtf dist to targetObj (scarab/campfire/anim/iceBaddie); also (s32)-compared */
    u8 unk2C4[0x2D0 - 0x2C4];
    void *targetObj; /* current attack/aggro target */
    u8 pad2D4[0x2F4 - 0x2D4];
    f32 nudgePosX; /* translation added to the model matrix as nudgePosProgress ramps */
    f32 nudgePosY;
    f32 nudgePosZ;
    f32 nudgeYaw; /* anim.rotX delta added as nudgeYawProgress ramps */
    BaddieStateExitFn stateExitFn; /* run once on control-mode change, then replaced by nextStateExitFn */
    union {
        int stateHandler; /* player state callback address */
        BaddieStateExitFn nextStateExitFn;
    };
    u8 unk30C[4];
    s32 queuedBitMask; /* 0x310: rebuilt every tick - zeroed, then OR'd with (1 << id)
        for each of the queuedBitCount queued bit ids; readers test bits 0x1/0x1000/0x4000 */
/* eventFlags bit: anim-event footstep - the anim/event stream latches it, and
 * the per-family update readers test-then-clear it to fire the footstep/climb
 * contact SFX. */
#define BADDIE_EVENT_FOOTSTEP 0x1
/* eventFlags bit: anim-event landing/impact - latched on a landing anim event,
 * test-then-cleared by the readers to fire the land sound / rumble / waterfx
 * splash. */
#define BADDIE_EVENT_LANDING 0x200
    s32 eventFlags; /* bits 1/0x200 observed */
    u32 heldButtons;
    int pressedButtons;
    u8 unk320[0x32E - 0x320];
    s16 stateTimer; /* count-up dt-accumulating timer, gated > 0x78, reset to 0 on state entry */
    s16 cameraYaw;
    u8 unk332[2];
    s16 turnRateAbs; /* abs(turnRate), written alongside it by dll_000F player_steerFromInput; the rideable-mount handlers (DIMSnowHorn1, HighTop, DR_CloudRunner) compare it against a turn threshold and clear it with turnRate when the stick falls under the deadzone */
    s16 turnRate; /* s16 angle units/sec: *yaw += k * (turnRate * timeDelta / speed) */
    s16 controlTimer; /* primary control-state timer; reset on mode entry and accumulated each update */
    u8 unk33A[0x33C - 0x33A];
    s32 curveId; /* active ROM curve, -1 = none; dll_000F player_findCurve stores gRomCurveInterface->find() here and player_updateCurve resolves it back through getById each frame */
    s32 unk340; /* initialised to -1 next to curveId */
    s8 curveSearchFilter; /* type filter passed as the last argument of gRomCurveInterface->find() when picking curveId */
    u8 unk345;
    s8 moveDone; /* set when the current move completes; SeqFns chain the next mode off it */
    u8 unk347[2];
    u8 hasTarget; /* cleared with death/reset */
    u8 moveChainFlags; /* bit0: chain-input window open (move progress within [slot+0x20, slot+0x24)); bit1: past the chain-commit progress (slot+0x28); bit2: next move queued (A pressed in the window, or the slot auto-chains) */
    u8 inputSector; /* quadrant of the stick heading relative to the actor's facing: 0 while the stick is inside the deadzone, else 1..4 from (4 - ((diff - 0x6000) / 0x4000)) in dll_000F player_steerFromInput; player.c switches the approach/turn move on it and copies it into PlayerState.moveChainIndex */
    s8 movementFlags; /* root-motion / velocity handling flags for the shared player controller */
    s8 stateTag; /* per-tick state/mode index (written each tick; compared ==1/==3 across the baddie cluster + player) */
    s8 unk34E;
    s8 lastHitPriority;
    u8 unk350[4];
    s8 hitPoints; /* remaining hit points; decremented on hit, < 1 = dead */
    u8 unk355;
    u8 moveEventFlags; /* one-shot move-progress event latches (bit1/bit2: SFX fired once past a progress threshold) */
    u8 unk357;
    u8 unk358;
    u8 unk359[0x35C - 0x359];
} BaddieState;

STATIC_ASSERT(sizeof(BaddieState) == 0x35C);
STATIC_ASSERT(offsetof(BaddieState, curvesCollision) == 0x004);
STATIC_ASSERT(offsetof(BaddieState, unk26C) ==
              offsetof(BaddieState, curvesCollision) + CURVES_COLLISION_STATE_SIZE);
STATIC_ASSERT(offsetof(BaddieState, controlMode) == 0x274);
STATIC_ASSERT(offsetof(BaddieState, moveJustStartedB) == 0x27B);
STATIC_ASSERT(offsetof(BaddieState, trackedObj) == 0x29C);
STATIC_ASSERT(offsetof(BaddieState, previousInputMagnitude) == 0x29C);
STATIC_ASSERT(offsetof(BaddieState, moveSpeed) == 0x2A0);
STATIC_ASSERT(offsetof(BaddieState, targetObj) == 0x2D0);
STATIC_ASSERT(offsetof(BaddieState, nudgePosX) == 0x2F4);
STATIC_ASSERT(offsetof(BaddieState, nudgeYaw) == 0x300);
STATIC_ASSERT(offsetof(BaddieState, eventFlags) == 0x314);
STATIC_ASSERT(offsetof(BaddieState, heldButtons) == 0x318);
STATIC_ASSERT(offsetof(BaddieState, pressedButtons) == 0x31C);
STATIC_ASSERT(offsetof(BaddieState, stateTimer) == 0x32E);
STATIC_ASSERT(offsetof(BaddieState, controlTimer) == 0x338);
STATIC_ASSERT(offsetof(BaddieState, moveDone) == 0x346);
STATIC_ASSERT(offsetof(BaddieState, hitPoints) == 0x354);

/*
 * GroundBaddiePlacement - the placement/setup record every ground baddie is
 * spawned from, i.e. the `config` argument of
 * BaddieControlInterface.initGroundBaddie. Decoded from
 * dll_19_initGroundBaddie (engine/25), the shared controller that reads the
 * whole record on behalf of every ground-baddie class: each field below is
 * named after the GroundBaddieState member the controller copies it into,
 * or after the object field it drives. Per-class re-uses exist (202's
 * crawler reads unk28 as a root-motion scale, hoodedZyck reads aggression as
 * a distance scale), so the class-specific slots stay unnamed.
 */
typedef struct GroundBaddiePlacement {
    ObjPlacement base; /* 0x00: standard object placement; base.ident gates the map-event save time */
    s16 gameBitA;      /* 0x18: mainGetBit gate -> obj->userData1 (inverted for romDefNo 636) */
    s16 gameBitC;      /* 0x1a */
    s16 gameBitD;      /* 0x1c: 202's paid-trigger baddie sets it on payment */
    s16 soundIdB;      /* 0x1e */
    s16 soundIdA;      /* 0x20 */
    s16 triggerId;     /* 0x22 */
    s16 unk24;         /* 0x24 */
    u8 pad26;          /* 0x26 */
    u8 initialWeaponId; /* 0x27 */
    u8 unk28;          /* 0x28 */
    u8 aggroRange;     /* 0x29: scaled <<3 into GroundBaddieState.aggroRange */
    u8 rotX;           /* 0x2a: 1/256-turn heading, sign-extended and <<8 into obj->anim.rotX */
    u8 flags;          /* 0x2b: GroundBaddieState.configFlags */
    s16 respawnDelay;  /* 0x2c: minutes fed to MapEvent addTime; 0 never respawns */
    s8 sequenceId;     /* 0x2e: -1 leaves the baddie dormant (obj->userData2 = 1) */
    u8 aggression;     /* 0x2f */
    s16 gameBitB;      /* 0x30: set 0 at init */
    u8 hitPoints;      /* 0x32: 0 means the default 6 */
    u8 pad33;          /* 0x33 */
} GroundBaddiePlacement;

STATIC_ASSERT(offsetof(GroundBaddiePlacement, gameBitA) == 0x18);
STATIC_ASSERT(offsetof(GroundBaddiePlacement, aggroRange) == 0x29);
STATIC_ASSERT(offsetof(GroundBaddiePlacement, flags) == 0x2B);
STATIC_ASSERT(offsetof(GroundBaddiePlacement, sequenceId) == 0x2E);
STATIC_ASSERT(offsetof(GroundBaddiePlacement, gameBitB) == 0x30);
STATIC_ASSERT(sizeof(GroundBaddiePlacement) == 0x34);

/*
 * GroundBaddieState - BaddieState plus the route/config tail shared by the
 * ground-bug baddie cluster (scarab dll_CA/CB/CE, iceBaddie; treasurechest
 * and lightfoot reference the same tail offsets). The 0x35C+ region is
 * PER-FAMILY in general: the dll_2E look-controller block sits at 0x35C for
 * DRpushcart/DIMSnowHorn1, 0x3EC for hightop, 0x4C4 for DR_CloudRunner -
 * which is why it is not part of BaddieState itself.
 */
typedef struct GroundBaddieState {
    BaddieState baddie;
    RouteNav routeNav; /* 0x35c: route destination/current/target and update budget */
    RouteState routeState; /* 0x384: allocated route nodes, heap, and recovered path */
    CharacterEyeAnimState eyeAnimState; /* 0x3ac: head-aim / eye-blink record (characterDoEyeAnims / characterSetHeadYawToTarget) */
    u8 pad3D4[0x3DC - 0x3D4];
    void *path; /* rom-curve/path record */
    void *savedPendingParentObj; /* obj+0xC0 swap slot around the player-interface update */
    f32 pathRadius;
    f32 glowAlpha; /* 0x3e8: alpha of the red glow tint RGBA(200,0,0,glowAlpha), passed to objSetGlowColor + objParticleFn alpha arg in baddie render */
    f32 glowRate; /* 0x3ec: per-frame delta added to glowAlpha; negated when the alpha ramp reaches its ceiling (ktrex) */
    s16 triggerId; /* config-sourced id (loaded from config+0x22) handed to BaddieControlInterface.spawnChild when a move/landing event fires */
    s16 gameBitA; /* set 1 on trigger */
    s16 gameBitB; /* set 1 / cleared 0; also passed to interface[10] */
    s16 gameBitC; /* gate; checked != -1 + mainGetBit */
    s16 gameBitD; /* 0x3f8: copy of GroundBaddiePlacement.gameBitD */
    s16 soundIdA; /* config-sourced sound-id (config+32); played via interface[+8]
        on the stop/cleanup path (dll19func12) and passed with soundIdB to the
        route/move interface [+0x3c] (dllcb/dllce/icebaddie) */
    s16 soundIdB; /* config-sourced sound-id (config+30); paired with soundIdA */
    u16 aggroRange; /* target-acquire radius passed to interface+0x48; (f32)(u32) conversions */
/* flags400 bit: baddie is advancing along its ROM curve path. Set once the
 * RomCurveWalker is successfully initialised (dll19func0), then each update
 * step calls Curve_AdvanceAlongPath while it is set and clears it at the end
 * of the path (dllcb). u16 field - no LL form needed. */
#define BADDIE_FLAG400_PATH_ACTIVE 0x8
    u16 flags400; /* bit flags 2/8/0x100; &flags400 also passed as a buffer base */
    s16 targetState; /* 0 = no target; tryAcquireTarget vs updateTargetMotion */
    u8 configFlags; /* bits 1/2/0x10 */
    u8 subMode; /* sub-state-machine index 0/1/2 (switch/==-tested; &subMode handed to BaddieControlInterface.processMessages as the route-phase out-param) */
    u8 aggression; /* percent-ish; randomGetRange(0, x), > 50 compares */
    u8 unk407[0x40A - 0x407];
    s8 lastHitSphereIndex;
    u8 unk40B;
    void *control; /* per-family control/extra record (engine-allocated; treasurechest casts its slot to LandedArwingState*) */
} GroundBaddieState;

STATIC_ASSERT(sizeof(GroundBaddieState) == 0x410);
STATIC_ASSERT(offsetof(GroundBaddieState, routeNav) == 0x35C);
STATIC_ASSERT(offsetof(GroundBaddieState, routeState) == 0x384);
STATIC_ASSERT(offsetof(GroundBaddieState, eyeAnimState) == 0x3AC);
STATIC_ASSERT(offsetof(GroundBaddieState, pathRadius) == 0x3E4);
STATIC_ASSERT(offsetof(GroundBaddieState, targetState) == 0x402);
STATIC_ASSERT(offsetof(GroundBaddieState, lastHitSphereIndex) == 0x40A);
STATIC_ASSERT(offsetof(GroundBaddieState, control) == 0x40C);

#endif /* MAIN_DLL_BADDIE_STATE_H_ */
