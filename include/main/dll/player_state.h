#ifndef MAIN_DLL_PLAYER_STATE_H_
#define MAIN_DLL_PLAYER_STATE_H_

#include "ghidra_import.h"
#include "global.h"
#include "main/dll/baddie_state.h"

typedef struct PlayerStatus {
    s8 health;
    s8 maxHealth;
    s8 animStateFlags;
    u8 unk3;
    s16 magic;
    s16 maxMagic;
    u8 money;
} PlayerStatus;

/*
 * PlayerState - player.c's obj+0xB8 "inner" record. The head is the
 * engine-wide BaddieState actor-control record (baddie_state.h); the
 * 0x35C+ tail is the player-private extension. Field widths mirror the
 * deref widths observed in player.c; unobserved ranges are padded.
 * 0x8E0 covers every observed access - the true allocation may be larger.
 */
/*
 * PlayerState.flags360 bit names. The field is a u32 but the retail source
 * writes the OR/AND-NOT masks with an LL suffix (64-bit compute, truncated on
 * store), so the SET/CLEAR defines carry LL to stay byte-identical.
 */
#define PLAYER_FLAG_AIM_READY 0x400LL         /* aim-screen coords valid: set after aim-position calc, gates the aimScreenX/Y getter */
#define PLAYER_FLAG_KNOCKBACK 0x800LL         /* knockback latched/in-progress: clear->init knockback timers, set->suppress further knockback damage */
#define PLAYER_FLAG_WATER_SPLASH_PENDING 0x20000LL /* queued water-entry FX: set on water-entry, gates spawnSplashBurst/spawnRipple then self-clears */
#define PLAYER_FLAG_WORLDPOS_OVERRIDE 0x8000000LL /* anim.modelState overrideWorldPos active: gates the localPos<->overrideWorldPos swap during render */
#define PLAYER_FLAG_LOCKED 0x200000LL         /* player controls locked (set/cleared by playerLock; gates pad-input processing) */
#define PLAYER_FLAG_HITDETECT 0x2LL           /* attack hit-detection active: set after ObjHitDetect setup, gates the objHitDetectFn sweep; cleared on state entry */
#define PLAYER_FLAG_NO_POS_VELOCITY 0x2000LL  /* suppress position-derived velocity: when set, velocityY is NOT recomputed from (worldPos-previousWorldPos)/dt; set on scripted-move state entry */
#define PLAYER_FLAG_LEDGE_DETECTED 0x100LL    /* nearby wall/ledge found: cleared at sweep start, set when the proximity sweep detects a blocking surface (records surfaceNormal); read via state getter case 11 */
#define PLAYER_FLAG_TELEPORTED 0x800000LL     /* position/yaw hard-set: set after any teleport/pos/yaw override, gates the snap-facing-to-heading branch then consumed */
#define PLAYER_FLAG_HEADING_LOCK 0x1000000LL  /* freeze input heading: when set, lastInputHeading is NOT updated from live input; set during committed turn/locomotion moves */

typedef struct PlayerState {
    BaddieState baddie;
    int playerStatus; /* PlayerStatus*; kept integer while raw decomp arithmetic remains */
    int flags360; /* player state flag word; bits 2/0x2000/0x800000/0x2000000... */
    u8 pad364[0x3C4 - 0x364];
    f32 fxOffsetX;
    f32 fxOffsetY;
    f32 fxOffsetZ;
    f32 fxOffset2X;
    f32 fxOffset2Y;
    f32 fxOffset2Z;
    int moveSlots; /* MoveSlot/HitDesc array base; indexed by moveSlotIndex, stride 0xB0 */
    int pendingParentObj;
    u8 pad3E4[0x3E8 - 0x3E4];
    u8 maxMagicUsed;
    u8 pad3E9[0x3F0 - 0x3E9];
    u8 flags3F0; /* state flag byte (bits read via >>N&1 and a ByteFlags overlay): bit4/5 move-mode gates, bit6/7 etc. */
    u8 flags3F1; /* state flag byte: bit0/bit4/bit5 gate locomotion/yaw-arc paths */
    u8 unk3F2;
    u8 flags3F3; /* state flag byte: bits 1/2/3 queried by accessor getters */
    u8 flags3F4; /* state flag byte: bit6 = path-follow/scripted-move gate */
    u8 pad3F5[0x3F6 - 0x3F5];
    u8 unk3F6;
    u8 fallSeverity; /* fall/landing severity tier (0-3) set from the fall height-difference (hdiff vs lbl_803E8104/8108/810C thresholds); selects the landing move/sfx (move 0xa/0x90) and at >=2 fires camera shake + a ground-impact ObjHits; reset to 0 on state change */
    int moveAnimTable; /* s16 anim/move-id table base; fed to ObjAnim_SetCurrentMove */
    u8 pad3FC[0x3FE - 0x3FC];
    u16 unk3FE;
    int moveParams; /* ptr to a 0x60 locomotion-parameter block (lbl_80333250); deref'd as f32 speed thresholds/limits at +4/+c/+10/+14/+18/+1c */
    f32 maxSpeed;
    f32 currentSpeed; /* player current movement speed; clamped to [0, maxSpeed], scaled by friction */
    u8 fallFrames; /* frames spent in the falling/airborne path (gravity applied to velocityY each tick); ++ per frame clamped to 10, reset to 0 on landing/state-entry; >5 (with flag 0x3f1:b01) fires the landing rumble + footstep sfx */
    u8 staffHoldFrames; /* frames the staff-hold/grab condition has persisted; ++ while held, reset to 0 on state changes, clamped to 10; >2 forces drop of carried object + staff action */
    u8 pad40E[0x410 - 0x40E];
    f32 rumbleCooldown; /* f32 countdown decremented by frame-time each tick, floored to 0; when expired (<=0) and moving fast (animSpeedA > thresh) fires doRumble + sfx 0x404 and resets to the cooldown interval */
    f32 buttonHoldTimer; /* accumulates frame-time while button 0x100 is held (and fn_802A9A0C true), clamped to a max; reset to 0 when released; paired with the 0x3f4:b20 "accumulating" flag */
    f32 actionCooldown; /* f32 input-cooldown countdown decremented by timeDelta each tick, floored to 0; gates button 0x100: when pressed and the timer has expired (<=0) performs the staff/aim action (fn_802AA014) and resets to the cooldown interval */
    u8 chargeCapacity; /* 0x41c: full-charge level for the breath attack (0x14 for move 0xc55, else 0xa); chargeLevel must reach this to fire, and -chargeCapacity is the damage applied to the target */
    u8 pad41D[0x420 - 0x41D];
    f32 leanCurveScale; /* lean-curve sample: Curve_EvalCatmullRom(leanCurve) indexed by targetYawRateSigned (default 1.0); multiplies targetYawRateLimit to bound the per-frame targetYaw delta */
    u8 pad424[0x428 - 0x424];
    f32 targetYawSmoothRate; /* curve1 sample (Curve_EvalCatmullRom @paramCurve1); 1/this = the interpolate() rate easing targetYaw toward inputHeading */
    f32 targetYawRateLimit;  /* curve2 sample (@paramCurve2); * leanCurve output bounds the per-frame targetYaw delta */
    f32 yawSmoothRate;       /* curve3 sample (@paramCurve3); 1/this = the interpolate() rate easing applied yaw toward targetYaw */
    f32 yawRateLimit;        /* curve4 sample (@paramCurve4); * timeDelta bounds the per-frame applied-yaw delta */
    f32 velSmoothRate;       /* curve0 sample (@paramCurve0); the interpolate() rate easing smoothVelX/Z toward maxSpeed*sin/cos(heading) */
    f32 waterCurrentVelA; /* smoothed local-space water-current velocity (interpolate toward playerCalcWaterCurrent rotated by yaw); added to baddie.animSpeedA when flag 0x3f0:b20 set */
    f32 waterCurrentVelB; /* smoothed local-space water-current velocity component; added to baddie.animSpeedB when flag 0x3f0:b20 set */
    f32 unk444;
    f32 unk448;
    u8 pad44C[0x450 - 0x44C];
    int paramCurve0; /* Catmull-Rom curve-data ptr (resource base+0x450); Curve_EvalCatmullRom(...) at speed u, feeds unk438 */
    int paramCurve1; /* curve-data ptr (base+0x4f4); feeds unk428 */
    int paramCurve2; /* curve-data ptr (base+0x598); feeds unk42C */
    int paramCurve3; /* curve-data ptr (base+0x650); feeds unk430 */
    int paramCurve4; /* curve-data ptr (base+0x6f4); feeds unk434 */
    int leanCurve;   /* Catmull-Rom curve-data ptr indexed by targetYawRateSigned (lean), feeds leanCurveScale */
    u8 pad468[0x46C - 0x468];
    int spawnedObject; /* object handle from Obj_SetupObject (player-spawned, e.g. staff/projectile setup) */
    f32 inputMagnitude;
    int inputHeading;
    s16 targetYaw; /* desired heading; copied into yaw when applied */
    u8 pad47A[0x47C - 0x47A];
    int targetYawRateSigned;
    int targetYawRate;
    s16 yaw; /* applied heading; drives sin/angle math */
    u8 pad486[0x488 - 0x486];
    int yawRateSigned;
    int yawRate;
    s16 prevYaw;
    s16 prevTargetYaw;
    int lastInputHeading;
    int bodyLeanRateSigned;
    int bodyLeanRate;
    u16 unk4A0;
    u16 unk4A2;
    int targetObjectBearing;    /* signed relative bearing to cameraTargetObject (targetObjectYaw - targetYaw, wrapped to +-0x8000) */
    int targetObjectBearingAbs; /* abs(targetObjectBearing); compared against 0x4000 (~90deg) to gate facing-target logic */
    int targetObjectYaw;        /* heading from player toward cameraTargetObject (getAngle(-dx,-dz)) */
    f32 targetObjectDist;       /* planar distance to cameraTargetObject (sqrt(dx^2+dz^2)) */
    u16 unk4B4;
    u8 pad4B6[0x4B8 - 0x4B6];
    void *cameraTargetObject; /* Camera_GetTarget() result; mirrored into gPlayerInteractTarget */
    u8 pad4BC[0x4C0 - 0x4BC];
    int lastHitObject;
    int groundObject; /* object the player stands on/rides; transform parent for relative pos, set from collision hit */
    f32 smoothVelX; /* smoothed planar velocity X; eased toward maxSpeed*sin(heading) */
    f32 smoothVelZ; /* smoothed planar velocity Z; magnitude = sqrt(x^2+z^2) -> animSpeedC */
    s16 headPitch;
    s16 bodyLeanHalf;
    s16 bodyLeanAngle;
    s16 headYaw;
    s16 unk4D8;
    s16 unk4DA;
    s16 unk4DC;
    s16 unk4DE;
    s16 unk4E0;
    u8 pad4E2[0x4E4 - 0x4E2];
    s8 climbStep; /* discrete climb/step level (++ up, -- down by moveInputZ); climbTargetY = climbStep*climbStepHeight + climbBaseY; >3 switches A-button icon */
    s8 climbStepCount; /* 0x4e5: total number of climb steps for the current climbable; climbStep >= climbStepCount-3 (within 3 of the top) selects the top-of-climb transition */
    u8 climbingUp; /* 0x4e6: climb direction, 1 while ascending (forward Y lerp start->target), 0 while descending (reverse lerp) */
    s8 climbSampleDone; /* 0x4e7: one-shot latch for the climb move's initial joint-transform sampling; while 0 (and moveId<=1) samples the start/end root motion into moveStartPosY then sets to 1 */
    f32 unk4E8;
    f32 climbBaseY; /* base local-Y for the climb-step lerp: climbTargetY = climbStep*climbStepHeight + climbBaseY */
    f32 climbStepHeight; /* per-step vertical rise; multiplied by climbStep to form climbTargetY */
    f32 climbTargetY; /* target localPosY for the current climb step (climbStep*climbStepHeight + climbBaseY); lerp endpoint */
    f32 climbStartY;  /* localPosY at climb-step start; lerp base: localPosY = progress*(climbTargetY-climbStartY) + climbStartY */
    f32 unk4FC;
    f32 moveStartPosY; /* localPosY captured at the start of the 0x35/0x37 vertical moves; the per-frame Y is interpolated between this anchor and the current localPosY by currentMoveProgress */
    f32 unk504;
    f32 unk508;
    f32 unk50C;
    u8 pad510[0x514 - 0x510];
    f32 unk514;
    f32 unk518;
    u8 pad51C[0x52C - 0x51C];
    f32 unk52C;
    u8 pad530[0x534 - 0x530];
    f32 unk534;
    f32 unk538[3];
    s16 unk544;
    s8 unk546;
    u8 unk547;
    u8 pad548[0x549 - 0x548];
    s8 unk549;
    u8 pad54A[0x54C - 0x54A];
    f32 spanTopY;    /* upper Y bound of the collision span (interpolated from SweepHit.g* at hit.gt); localPosY is clamped/checked against [spanBottomY, spanTopY] */
    f32 spanBottomY; /* lower Y bound of the collision span (interpolated from SweepHit.fz0/fz1) */
    u8 pad554[0x560 - 0x554];
    f32 moveOffsetY; /* local-space root/move displacement vector (offsetX at 0x564, Y at 0x560, Z at 0x568); scaled by moveProgress and added to localPos for camera overridePos; derived from joint-transform samples + groundNormal */
    f32 moveOffsetX;
    f32 moveOffsetZ;
    f32 groundNormalX; /* surface normal (nx,ny,nz,nw) from the move-anchor collision query; getAngle(X,Z) drives targetYaw on slopes, used as a slide basis */
    f32 groundNormalY;
    f32 groundNormalZ;
    f32 groundNormalW;
    f32 slopeTangentX; /* horizontal tangent to the ground plane (= -groundNormalZ); the (slopeTangentX, slopeTangentY, slopeTangentZ) vector is the ground normal rotated 90deg in XZ, used to project movement along the slope */
    f32 slopeTangentY; /* ground-tangent Y component, always 0 (the tangent is horizontal) */
    f32 slopeTangentZ; /* ground-tangent Z component (= groundNormalX) */
    f32 slopePlaneD; /* signed plane-distance term for the slope-tangent plane: -(point . slopeTangent), computed when the ground tangent is captured */
    f32 unk58C;
    u8 pad590[0x594 - 0x590];
    f32 unk594;
    u8 pad598[0x5A4 - 0x598];
    s16 animEventState; /* anim event-state word written each frame via ObjAnim_WriteStateWord(...EVENT_STATE); from fn_802A71E0 or a scaled move-blend factor */
    s16 moveAltToggle; /* alternating selector for a paired repeating move: !=0 picks move 0x15, ==0 picks 0x16; XOR-toggled each cycle (e.g. left/right climb step) */
    f32 unk5A8;
    f32 unk5AC;
    f32 unk5B0;
    f32 moveStartX; /* local-space start position captured at move begin; localPos = progress*(moveEnd-moveStart)+moveStart */
    f32 moveStartY;
    f32 moveStartZ;
    int launchYaw; /* heading captured (*(s16*)obj) when a jump/launch move starts; base angle for the airborne arc yaw (case 7) */
    f32 unk5C4;
    u8 pad5C8[0x5CC - 0x5C8];
    f32 unk5CC;
    u8 pad5D0[0x5D4 - 0x5D0];
    f32 unk5D4;
    f32 unk5D8;
    f32 unk5DC;
    u8 pad5E0[0x5EC - 0x5E0];
    f32 moveEndX; /* local-space target position for the move lerp (paired with moveStart) */
    f32 moveEndY;
    f32 moveEndZ;
    f32 moveEnd2X; /* secondary local-space target position, also lerped from moveStart */
    f32 moveEnd2Y;
    f32 moveEnd2Z;
    s16 unk604;
    u8 unk606;
    u8 unk607;
    u8 unk608;
    u8 unk609;
    u8 pad60A[0x60C - 0x60A];
    f32 hitNormalX; /* collision-hit surface normal (nx,ny,nz,nw from SweepHit) captured during a wall/slide probe; getAngle(X,Z) sets targetYaw for the slide move */
    f32 hitNormalY;
    f32 hitNormalZ;
    f32 hitNormalW;
    f32 unk61C;
    f32 unk620;
    f32 unk624;
    f32 unk628;
    f32 unk62C;
    f32 unk630;
    f32 unk634;
    u8 pad638[0x63C - 0x638];
    f32 unk63C;
    f32 traveledDistance;
    f32 travelTargetDistance; /* PSVECMag(start->target); traveledDistance is compared against it */
    f32 avoidVelX; /* planar steering/separation velocity X: nudged by cos/sin avoidance sums, damped, magnitude-clamped, *= timeDelta -> position delta */
    f32 avoidVelZ;
    u8 pad650[0x654 - 0x650];
    f32 surfaceNormalX; /* surface normal from the last collision sweep (SweepHit.n*); dotted with movement dir, drives slide angle (getAngle(X,Z)) and position offset */
    f32 surfaceNormalY;
    f32 surfaceNormalZ;
    f32 unk660;
    f32 unk664;
    f32 unk668;
    f32 unk66C;
    u8 pad670[0x67C - 0x670];
    int contactObject; /* collision hit object the player is anchored to; local-space contact point stored at 0x664/0x668/0x66C, 0 when in free space */
    u8 pad680[0x681 - 0x680];
    s8 unk681;
    u8 surfaceDir; /* dominant surface-normal axis+sign (0=+X,1=-X,2=+Z,3=-Z); picks the wall slide/climb anim variant */
    u8 pad683[0x684 - 0x683];
    int interactObject; /* object the player is interacting with; ObjMsg_SendToObject recipient, cleared after */
    s16 unk688;
    u8 pad68A[0x6A4 - 0x68A];
    f32 unk6A4;
    f32 unk6A8;
    f32 unk6AC;
    f32 unk6B0;
    f32 warpStartX; /* local-space start position for a scripted warp/teleport move lerp; localPos = progress*warpDelta + warpStart, also drives camera overridePos */
    f32 warpStartY;
    f32 warpStartZ;
    f32 warpDeltaX; /* local-space displacement to the warp target (start->target); paired with warpStart for the move/camera lerp */
    f32 warpDeltaY;
    f32 warpDeltaZ;
    u8 warpKind; /* 0x6cc: warp-point kind from the pad/warp vtable query; ==1 exits +90deg, else -90deg */
    u8 pad6CD[0x6D0 - 0x6CD];
    s32 stickX;
    s32 stickY;
    f32 stickYf;
    f32 stickXf;
    u16 buttonsHeld;
    u16 buttonsJustPressed;
    u16 buttonsJustPressedIfNotBusy;
    u8 pad6E6[0x6E8 - 0x6E6];
    int moveSequence; /* pointer to the active s16 move/anim descriptor (entries at +2/+8/+a) */
    u8 moveSequenceFlags; /* behavior bits 0x1/0x4/0x8 selecting blend/progress handling */
    u8 pad6ED[0x768 - 0x6ED];
    f32 savedPosX;
    f32 savedPosY;
    f32 savedPosZ;
    u8 pad774[0x778 - 0x774];
    f32 probeHitDist; /* hit distance (SweepHit.dist) from a directional collision probe (objBboxFn_800640cc); has a getter (fn_802966F4), reset to 0 on state changes */
    f32 unk77C;
    u8 pad780[0x784 - 0x780];
    f32 verticalVel; /* vertical velocity factor applied as anim.velocityY = verticalVel*fv; has dedicated get/set (fn_80296220), drives climb/descend move progress */
    f32 aimScreenY; /* aim-cursor screen Y (centered at halfH), driven by stick aimInputX; unprojected to a world aim direction */
    f32 aimScreenX; /* aim-cursor screen X (centered at halfW), driven by stick aimInputZ; unprojected to a world aim direction */
    u8 pad790[0x79C - 0x790];
    f32 knockbackTimer; /* knockback/stagger countdown (-= timeDelta*knockbackDrainRate); set on knock moves, gates knock FX/sfx (0x394/0x395) while >0, reset to 0 on expiry */
    f32 knockbackHitTimer; /* periodic countdown during knockback drag (-= timeDelta); on expiry fires an ObjHits position-hit and reloads */
    f32 knockbackDrainRate; /* drain multiplier for knockbackTimer (-= timeDelta*this); tracks velocity magnitude, clamped to a range */
    u8 unk7A8;
    u8 pad7A9[0x7B8 - 0x7A9];
    f32 aimInputX; /* smoothed aim-stick X (eased from baddie.moveInputX, clamped); drives aimScreenY and the world aim direction */
    f32 aimInputZ; /* smoothed aim-stick Z (eased from baddie.moveInputZ, clamped); drives aimScreenX and the world aim direction */
    u8 pad7C0[0x7C8 - 0x7C0];
    f32 sinkOffsetY; /* vertical sink/bob offset added to localPosY (e.g. sinking into snow during the snowstep move); accumulates and clamps, decays back toward 0 */
    f32 unk7CC;
    f32 unk7D0;
    f32 chargeLevel; /* charge/breath meter: builds (+= K*fv) while a charge move's button is held, drains (-= K*dt) and floors at 0 otherwise; at capacity (unk41C) fires the charged attack; (u8) value fed to fn_8011F34C */
    f32 unk7D8;
    f32 unk7DC;
    f32 curveSpeedScale; /* speed->curve-sample multiplier: u = speed*curveSpeedScale, the eval position into paramCurve0-4 */
    u8 pad7E4[0x7EC - 0x7E4];
    int unk7EC;
    int focusObject; /* object handle for camera setFocus / sequence-trigger interactions */
    u8 pad7F4[0x7F8 - 0x7F4];
    int heldObj; /* carried object (playerSetHeldObject) */
    f32 unk7FC;
    u8 isHoldingObject; /* 1 while carrying a held object (set with heldObj on pickup msgs 0x100008/0x100010); cleared to 0 on release/state resets */
    u8 pad801[0x806 - 0x801];
    u16 staffAnimState; /* staff grow/shrink anim state machine (fn_802AEF34): 0/1=shrink,2=grow,3=settle,0xf=variant */
    u16 hitIntervalTimer; /* countdown (-= dt) reset to 0x3c on expiry, firing a periodic ObjHits record */
    s16 animState;
    s16 queuedItemCommand; /* primary queued item/use command id from ObjMsg 0x80002; -1 = none; processed by playerProcessQueuedItemCommand */
    s16 deferredItemCommand; /* item command (0x2d/0x5ce) deferred while a target object is engaged; -1 = none; consumed/cleared once resolved */
    s16 stepEventTimer; /* countdown (-= framesThisStep); on expiry reloads interval from lbl_803DC6A8[gaitStepLevel] and advances stepDustCount */
    s16 idleWaitTimer;
    f32 idleHoldTimer; /* seconds the current idle move has been held; += timeDelta, clamped */
    u8 pad818[0x81A - 0x818];
    s16 characterId;
    s16 pendingBoneEffectId; /* one-shot bone-particle effect id (set by fn_802960E8); spawned via gBoneParticleEffectInterface->spawnEffect then cleared to 0 */
    s16 unk81E;
    f32 cutsceneTimer; /* time-stop/cutscene countdown (-= dt while >0); on expiry calls cutsceneEnterExit(0,0)+sets cutsceneEnded, at threshold lbl_803E7EF0 calls cutsceneEnterExit(1,0)+setTimeStop */
    f32 unk824;
    f32 hitTimer; /* per-hit countdown for multi-hit moves; -= dt, on <=0 records an ObjHits hit and reloads from hitInterval; gates hitCount */
    f32 targetAnimSpeed; /* interpolate() target for baddie.animSpeedA */
    f32 velSmoothRateBase; /* per-surface default that velSmoothRate is reset to (set by surfaceType: 0x803E8144 default, 0x803E8118 case13, 0x803E7F6C case3) */
    f32 unk834;
    f32 waterDepth; /* waterSurfaceY - worldPosY; player's submerged depth, drives splash/ripple FX */
    f32 waterSurfaceY; /* water surface world-Y (from cfg+0x1c0); compared against worldPosY */
    f32 speedScale; /* 0-1 movement-speed multiplier from terrain (water depth / slope); currentSpeed = (maxSpeed-K) * (t * speedScale) */
    f32 unk844;
    f32 prevWorldPosY;
    f32 groundRefY; /* 0x84C: worldPosY latched when grounded */
    f32 fallThresholdY; /* 0x850: groundRefY minus a margin; worldPosY <= this triggers the fall path */
    f32 stateTimer; /* per-frame countdown (-= timeDelta), reset to a constant on expiry */
    int unk858;
    f32 turnDeadzoneScale;
    u8 pad860[0x86C - 0x860];
    u8 surfaceType;
    s8 stickDirection;
    u8 latchedStickDir; /* latched stick-direction code (0..4) from the prior frame's edge/collision probe; compared against the current stickDirection to detect a held/repeated direction (gates the press-vs-hold move + speed branch); reset to 0 when the direction changes */
    u8 stopMoveIndex; /* cycling index into gPlayerStopMoves[], advanced %3 */
    u8 pad870[0x874 - 0x870];
    f32 unk874;
    f32 particleBurstCooldown; /* f32 countdown decremented by frame-time each tick, floored to 0; while moving fast, on expiry (<=0) spawns a burst of particle FX (spawnObject 0x804) then resets to the burst interval */
    f32 targetSuppressTimer; /* f32 countdown decremented by frame-time each tick, floored to 0; set on a state transition (flag 0x3f2:b40); while active (>0, queried via fn_80295C24) suppresses A-button-hint camera targeting */
    f32 idleDelayTimer; /* idle-eligibility countdown (f32); set positive at state init (lbl_803E7FA4), decremented by frame-time in fn_802B18BC and floored at 0; the default-idle "stay" path requires it == 0 */
    u32 flags884; /* 0x884: directional-response flag word (set in another TU); bit0 gates the rumble + directional anim branch, bits 2/4/8 select the directional move index (idx 3/1/2) into the move table */
    f32 animSpeedDecay; /* 0x888: per-frame decay rate for baddie.animSpeedA via powfBitEstimate(rate, dt) */
    f32 animSpeedStart; /* 0x88c: initial baddie.animSpeedA magnitude at move start (set as animSpeedA = -animSpeedStart) */
    f32 pushVelX; /* planar push/displacement velocity X: eased toward a target push via interpolate, decayed by powfBitEstimate, snapped to 0 near zero; added to the transformed world position */
    f32 pushVelZ;
    int stateHandler; /* staged state/anim handler fn-ptr (stored as int); copied into baddie.unk304 handler slot on anim change */
    u16 unk89C;
    u8 pad89E[0x8A0 - 0x89E];
    u16 periodicHitTimer; /* accumulates dt; on crossing 0x78 wraps (-=0x78) and fires a periodic ObjHits position-hit */
    u8 moveVariantIndex; /* index into moveAnimTable->moves[]/angles[] (0xff = none) */
    u8 walkAnimSoundId; /* anim-sound-set id copied into animSoundId for low gait (gaitStepLevel <= 3); init 3 */
    u8 runAnimSoundId;  /* anim-sound-set id copied into animSoundId for high gait (gaitStepLevel > 3); init 4 */
    u8 footstepSoundId; /* sound-variant id passed with surfaceType to audioPickSoundEffect_8006ed24 for footstep/landing sfx */
    u8 animSoundId; /* active anim-event sound set passed to the animEvents audio dispatch (objAudioFn_8006ef38/edcc); selected from walk/run/altAnimSoundId by gait/move */
    u8 altAnimSoundId; /* anim-sound-set id copied into animSoundId for specific moves (e.g. turn/launch); init 6 */
    u8 moveSlotCount;
    u8 moveSlotIndex;
    u8 altMoveToggle; /* 0x8aa: alternating selector XOR-toggled each invocation; when nonzero picks the alternate approach move (0x1a) -- sibling of moveAltToggle */
    u8 hitCount; /* hits dealt so far in the current multi-hit move; ++ per hit, stops when >= hitCountMax */
    u8 hitCountMax; /* max hits for the move (HitDesc.valsB[0]) */
    u8 hitInterval; /* frames between hits (HitDesc.valsA[0]); reloads hitTimer */
    u8 pad8AE[0x8B0 - 0x8AE];
    u8 gaitStepLevel; /* gait/step level 1-4 (capped) derived from gaitLevel; indexes step-interval tables lbl_803DC6A8/lbl_803DC6B0 */
    u8 stepDustCount; /* footstep dust-particle burst counter loaded from lbl_803DC6B0[gaitStepLevel]; decremented per frame, spawns dust while nonzero */
    u8 pad8B2[0x8B3 - 0x8B2];
    u8 staffGrown; /* 1 when the staff is grown/extended (set by staffDoGrowShrinkAnim grow path) */
    u8 staffActionRequest; /* pending staff grow/shrink action: 0=none,1=shrink,2=begin-grow,4=grow */
    u8 pad8B5[0x8B8 - 0x8B5];
    u8 queuedBitCount; /* count (0..4) of queued bit-index bytes stored in the following array at 0x8b9; a "case 1" push appends a byte and increments this, clamped to 4; on state init the loop ORs (1 << each stored byte) into the bitmask at 0x310 then this is reset to 0 */
    u8 pad8B9[0x8BF - 0x8B9]; /* queued bit-index byte array filled by the queuedBitCount push API */
    u8 unk8BF;
    u8 unk8C0;
    u8 unk8C1;
    s8 unk8C2;
    u8 unk8C3;
    u8 unk8C4;
    u8 emissionState; /* emission-controller lifecycle state code (0-4) set by the staff/move handler keyed on current move; returned by EmissionController_IsLingering */
    u8 pad8C6[0x8C7 - 0x8C6];
    u8 staffUnlockedFlags;
    u8 curAnimId; /* current move/anim id (0x44 = default) */
    u8 cameraFlags; /* flags word accumulated via |= (e.g. bit 2) and passed to the camera interface (gCameraInterface slot 0x68) on state change; reset to 0 on state entry */
    u8 unk8CA;
    u8 pad8CB[0x8CC - 0x8CB];
    s8 gaitLevel; /* locomotion gait level, stepped by 4 in [0,0x14] by speed thresholds; /4*2 indexes the move/gait tables (drives gaitStepLevel 1-4) */
    s8 activeHitWindow; /* index (0-2) of the currently-active hit window in the move's HitDesc list; -1 = none active */
    s8 hitWindowIndex; /* latched copy of activeHitWindow used to index per-window hit data (offset *4) */
    u8 cutsceneEnded; /* one-shot flag set to 1 when cutsceneTimer expires and cutsceneEnterExit(0,0) runs (in playerUpdate / playerUpdateWhileTimeStopped); cleared to 0 on a new move start; signals the cutscene/time-stop just finished */
    u8 unk8D0;
    u8 unk8D1;
    u8 unk8D2;
    u8 unk8D3;
    u8 unk8D4;
    u8 pad8D5[0x8D8 - 0x8D5];
    u16 pendingFxFlags; /* one-shot particle-effect request bits (1/2/8 spray-splash, 4 landing burst); set on events, cleared after the FX is spawned */
    u8 pad8DA[0x8DC - 0x8DA];
    int unk8DC;
} PlayerState;

STATIC_ASSERT(sizeof(PlayerState) == 0x8E0);
STATIC_ASSERT(offsetof(PlayerStatus, magic) == 0x4);
STATIC_ASSERT(offsetof(PlayerStatus, maxMagic) == 0x6);
STATIC_ASSERT(offsetof(PlayerStatus, money) == 0x8);
STATIC_ASSERT(offsetof(PlayerState, playerStatus) == 0x35C);
STATIC_ASSERT(offsetof(PlayerState, targetYaw) == 0x478);
STATIC_ASSERT(offsetof(PlayerState, heldObj) == 0x7F8);
STATIC_ASSERT(offsetof(PlayerState, pendingFxFlags) == 0x8D8);

#endif /* MAIN_DLL_PLAYER_STATE_H_ */
