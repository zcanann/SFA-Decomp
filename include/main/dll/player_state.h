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
    u8 unk3F0;
    u8 unk3F1;
    u8 unk3F2;
    u8 unk3F3;
    u8 unk3F4;
    u8 pad3F5[0x3F6 - 0x3F5];
    u8 unk3F6;
    u8 unk3F7;
    int moveAnimTable; /* s16 anim/move-id table base; fed to ObjAnim_SetCurrentMove */
    u8 pad3FC[0x3FE - 0x3FC];
    u16 unk3FE;
    int unk400;
    f32 maxSpeed;
    f32 currentSpeed; /* player current movement speed; clamped to [0, maxSpeed], scaled by friction */
    u8 unk40C;
    u8 unk40D;
    u8 pad40E[0x410 - 0x40E];
    f32 unk410;
    f32 unk414;
    f32 unk418;
    u8 unk41C;
    u8 pad41D[0x420 - 0x41D];
    f32 unk420;
    u8 pad424[0x428 - 0x424];
    f32 unk428;
    f32 unk42C;
    f32 unk430;
    f32 unk434;
    f32 unk438;
    f32 unk43C;
    f32 unk440;
    f32 unk444;
    f32 unk448;
    u8 pad44C[0x450 - 0x44C];
    int unk450;
    int unk454;
    int unk458;
    int unk45C;
    int unk460;
    int unk464;
    u8 pad468[0x46C - 0x468];
    int unk46C;
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
    int unk4A4;
    int unk4A8;
    int unk4AC;
    f32 unk4B0;
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
    s8 unk4E4;
    s8 unk4E5;
    u8 unk4E6;
    s8 unk4E7;
    f32 unk4E8;
    f32 unk4EC;
    f32 unk4F0;
    f32 unk4F4;
    f32 unk4F8;
    f32 unk4FC;
    f32 unk500;
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
    u8 pad538[0x544 - 0x538];
    s16 unk544;
    s8 unk546;
    u8 unk547;
    u8 pad548[0x549 - 0x548];
    s8 unk549;
    u8 pad54A[0x54C - 0x54A];
    f32 unk54C;
    f32 unk550;
    u8 pad554[0x560 - 0x554];
    f32 unk560;
    f32 unk564;
    f32 unk568;
    f32 unk56C;
    f32 unk570;
    f32 unk574;
    f32 unk578;
    f32 unk57C;
    f32 unk580;
    f32 unk584;
    f32 unk588;
    f32 unk58C;
    u8 pad590[0x594 - 0x590];
    f32 unk594;
    u8 pad598[0x5A4 - 0x598];
    s16 unk5A4;
    s16 unk5A6;
    f32 unk5A8;
    f32 unk5AC;
    f32 unk5B0;
    f32 unk5B4;
    f32 unk5B8;
    f32 unk5BC;
    int unk5C0;
    f32 unk5C4;
    u8 pad5C8[0x5CC - 0x5C8];
    f32 unk5CC;
    u8 pad5D0[0x5D4 - 0x5D0];
    f32 unk5D4;
    f32 unk5D8;
    f32 unk5DC;
    u8 pad5E0[0x5EC - 0x5E0];
    f32 unk5EC;
    f32 unk5F0;
    f32 unk5F4;
    f32 unk5F8;
    f32 unk5FC;
    f32 unk600;
    s16 unk604;
    u8 unk606;
    u8 unk607;
    u8 unk608;
    u8 unk609;
    u8 pad60A[0x60C - 0x60A];
    f32 unk60C;
    f32 unk610;
    f32 unk614;
    f32 unk618;
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
    f32 unk648;
    f32 unk64C;
    u8 pad650[0x654 - 0x650];
    f32 unk654;
    f32 unk658;
    f32 unk65C;
    f32 unk660;
    f32 unk664;
    f32 unk668;
    f32 unk66C;
    u8 pad670[0x67C - 0x670];
    int unk67C;
    u8 pad680[0x681 - 0x680];
    s8 unk681;
    u8 unk682;
    u8 pad683[0x684 - 0x683];
    int interactObject; /* object the player is interacting with; ObjMsg_SendToObject recipient, cleared after */
    s16 unk688;
    u8 pad68A[0x6A4 - 0x68A];
    f32 unk6A4;
    f32 unk6A8;
    f32 unk6AC;
    f32 unk6B0;
    f32 unk6B4;
    f32 unk6B8;
    f32 unk6BC;
    f32 unk6C0;
    f32 unk6C4;
    f32 unk6C8;
    u8 unk6CC;
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
    f32 unk778;
    f32 unk77C;
    u8 pad780[0x784 - 0x780];
    f32 unk784;
    f32 unk788;
    f32 unk78C;
    u8 pad790[0x79C - 0x790];
    f32 unk79C;
    f32 unk7A0;
    f32 unk7A4;
    u8 unk7A8;
    u8 pad7A9[0x7B8 - 0x7A9];
    f32 unk7B8;
    f32 unk7BC;
    u8 pad7C0[0x7C8 - 0x7C0];
    f32 unk7C8;
    f32 unk7CC;
    f32 unk7D0;
    f32 unk7D4;
    f32 unk7D8;
    f32 unk7DC;
    f32 unk7E0;
    u8 pad7E4[0x7EC - 0x7E4];
    int unk7EC;
    int focusObject; /* object handle for camera setFocus / sequence-trigger interactions */
    u8 pad7F4[0x7F8 - 0x7F4];
    int heldObj; /* carried object (playerSetHeldObject) */
    f32 unk7FC;
    u8 unk800;
    u8 pad801[0x806 - 0x801];
    u16 staffAnimState; /* staff grow/shrink anim state machine (fn_802AEF34): 0/1=shrink,2=grow,3=settle,0xf=variant */
    u16 hitIntervalTimer; /* countdown (-= dt) reset to 0x3c on expiry, firing a periodic ObjHits record */
    s16 animState;
    s16 queuedItemCommand; /* primary queued item/use command id from ObjMsg 0x80002; -1 = none; processed by playerProcessQueuedItemCommand */
    s16 deferredItemCommand; /* item command (0x2d/0x5ce) deferred while a target object is engaged; -1 = none; consumed/cleared once resolved */
    s16 stepEventTimer; /* countdown (-= framesThisStep); on expiry reloads interval from lbl_803DC6A8[unk8B0] and advances unk8B1 */
    s16 idleWaitTimer;
    f32 idleHoldTimer; /* seconds the current idle move has been held; += timeDelta, clamped */
    u8 pad818[0x81A - 0x818];
    s16 characterId;
    s16 pendingBoneEffectId; /* one-shot bone-particle effect id (set by fn_802960E8); spawned via gBoneParticleEffectInterface->spawnEffect then cleared to 0 */
    s16 unk81E;
    f32 unk820;
    f32 unk824;
    f32 unk828;
    f32 targetAnimSpeed; /* interpolate() target for baddie.animSpeedA */
    f32 unk830;
    f32 unk834;
    f32 waterDepth; /* waterSurfaceY - worldPosY; player's submerged depth, drives splash/ripple FX */
    f32 waterSurfaceY; /* water surface world-Y (from cfg+0x1c0); compared against worldPosY */
    f32 unk840;
    f32 unk844;
    f32 prevWorldPosY;
    f32 unk84C;
    f32 unk850;
    f32 stateTimer; /* per-frame countdown (-= timeDelta), reset to a constant on expiry */
    int unk858;
    f32 turnDeadzoneScale;
    u8 pad860[0x86C - 0x860];
    u8 surfaceType;
    s8 stickDirection;
    u8 unk86E;
    u8 stopMoveIndex; /* cycling index into gPlayerStopMoves[], advanced %3 */
    u8 pad870[0x874 - 0x870];
    f32 unk874;
    f32 unk878;
    f32 unk87C;
    f32 unk880;
    u32 unk884;
    f32 unk888;
    f32 unk88C;
    f32 unk890;
    f32 unk894;
    int stateHandler; /* staged state/anim handler fn-ptr (stored as int); copied into baddie.unk304 handler slot on anim change */
    u16 unk89C;
    u8 pad89E[0x8A0 - 0x89E];
    u16 periodicHitTimer; /* accumulates dt; on crossing 0x78 wraps (-=0x78) and fires a periodic ObjHits position-hit */
    u8 moveVariantIndex; /* index into moveAnimTable->moves[]/angles[] (0xff = none) */
    u8 unk8A3;
    u8 unk8A4;
    u8 unk8A5;
    u8 unk8A6;
    u8 unk8A7;
    u8 moveSlotCount;
    u8 moveSlotIndex;
    u8 unk8AA;
    u8 unk8AB;
    u8 unk8AC;
    u8 unk8AD;
    u8 pad8AE[0x8B0 - 0x8AE];
    u8 unk8B0;
    u8 unk8B1;
    u8 pad8B2[0x8B3 - 0x8B2];
    u8 staffGrown; /* 1 when the staff is grown/extended (set by staffDoGrowShrinkAnim grow path) */
    u8 staffActionRequest; /* pending staff grow/shrink action: 0=none,1=shrink,2=begin-grow,4=grow */
    u8 pad8B5[0x8B8 - 0x8B5];
    u8 unk8B8;
    u8 pad8B9[0x8BF - 0x8B9];
    u8 unk8BF;
    u8 unk8C0;
    u8 unk8C1;
    s8 unk8C2;
    u8 unk8C3;
    u8 unk8C4;
    u8 unk8C5;
    u8 pad8C6[0x8C7 - 0x8C6];
    u8 staffUnlockedFlags;
    u8 curAnimId; /* current move/anim id (0x44 = default) */
    u8 unk8C9;
    u8 unk8CA;
    u8 pad8CB[0x8CC - 0x8CB];
    s8 unk8CC;
    s8 unk8CD;
    s8 unk8CE;
    u8 unk8CF;
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
