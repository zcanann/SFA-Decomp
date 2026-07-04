#ifndef MAIN_DLL_TRICKY_STATE_H_
#define MAIN_DLL_TRICKY_STATE_H_

#include "ghidra_import.h"
#include "global.h"
#include "main/dll/curve_walker.h"

/* Shared TrickyState.stateFlags bits used across the Tricky sidekick / spawned
 * sibling handlers (tricky, tricky_substates, trickyfollow, tumbleweedbush,
 * weaponE6). tricky.c keeps its own local names for the flame-child variant of
 * the 0x800/0x1000 child-spawn machine; these are the generic cross-consumer
 * names for the same bits. */
#define TRICKY_STATE_FLAG_CHILDREN_ACTIVE 0x800    /* spawned child objects are active */
#define TRICKY_STATE_FLAG_CHILDREN_CLEANUP 0x1000  /* child objects torn down this cycle */
#define TRICKY_STATE_FLAG_MOVE_ADVANCING 0x8000000 /* ObjAnim_AdvanceCurrentMove reported the current move still advancing */

/*
 * TrickyState - the obj+0xB8 extra record for the Tricky sidekick handlers
 * in grenade.c (trickyFn_* / trickyFoodFn_* / trickyFlameFn_* take it as
 * "state"). Field widths mirror the deref widths observed in grenade.c;
 * unobserved ranges are padded (observed in grenade.c, weaponE6.c, collectable.c, sidekickToy.c).
 * Tricky_getExtraSize returns 0x83C; sizeof kept at the 0x840 alloc rounding.
 */
typedef struct TrickyState {
    int progressPtr; /* MapEventInterface getProgressPtr() result (init) */
    int playerObj; /* owning player/sidekick object */
    u8 unk08;
    u8 unk09;
    u8 substate; /* anim-sequence substate 0..7 */
    u8 unk0B;
    u8 unk0C;
    s8 unkD;
    u8 padE[0x10 - 0xE];
    f32 prevSpeed;
    f32 speed; /* planar speed magnitude, multiplied into dirX/dirZ */
    f32 animTransitionTimer;
    u8 pad1C[0x20 - 0x1C];
    int moveId; /* compared to anim.currentMove, passed to ObjAnim_SetCurrentMove */
    u8 *followObj; /* the followed object (playerObj/target/found stores; dll vtable dispatched) */
    u8 *targetPosPtr; /* pointer to the current target/path position (compared to previousPathPoint; fed to fn_8004B31C as the position arg) */
    f32 dirX; /* normalized planar direction (pos delta / length) */
    f32 dirZ;
    f32 moveProgress; /* passed to ObjAnim_SetMoveProgress */
    f32 moveProgressTarget;
    f32 unk3C;
    f32 sidestepDelta;
    f32 backstepDelta;
    f32 verticalDelta;
    f32 rotStepScale;
    u32 pendingStateFlags;
    u32 stateFlags; /* the TRICKY state flag word (bit masks 0x80..0x100000) */
    u8 statusFlags;
    u8 pad59[0x5A - 0x59];
    s16 unk5A;
    u32 heightTrackObjId;
    f32 trackedHeight;
    u8 pad64[0x8C - 0x64];
    f32 prevLocalPosX;
    f32 prevLocalPosY;
    f32 prevLocalPosZ;
    u16 patch[4]; /* curve-walk patch values (dll_DF trickyFn_8013b368); the
                     indexed s16 copy loop stays raw */
    u8 padA0[0xD0 - 0xA0]; /* 0xA0: f32 triples at stride 0xC (walker, raw) */
    u16 unkD0;
    u16 unkD2;
    u8 padD4[0xE0 - 0xD4];
    f32 homePosX; /* home position, init from obj world pos */
    f32 homePosY;
    f32 homePosZ;
    u8 padEC[0xF8 - 0xEC];
    u32 pathControlFlags; /* head word of the embedded gPathControlInterface record */
    u8 pathControlData[0x1B8 - 0xFC]; /* embedded gPathControlInterface record (0xF8..0x1B8) */
    f32 nearestSpecialDeltaY; /* signed dy to the nearest special-surface (type 0xe) floor hit */
    u8 pad1BC[0x25F - 0x1BC];
    u8 physicsActive; /* same actor-record slot as BaddieState.physicsActive (free-fall physics enable) */
    u8 unk260;
    u8 unk261;
    u8 pad262[0x264 - 0x262];
    u8 surfaceFlags; /* TRICKY_SURFACE_FLAG_* (HAS_NEARBY_FLOOR etc.) */
    u8 pad265[0x290 - 0x265];
    s16 pathRotY;
    s16 pathRotZ;
    u8 pad294[0x29C - 0x294];
    u32 actionTargetObj;
    u16 turnOctant; /* (u16 angleDelta >> 13): which 1/8 sector the turn falls in; used as an anim mode */
    u16 unk2A2;
    u16 targetDist; /* distance to actionTargetObj: (s16)sqrt(dx^2+dy^2+dz^2) */
    u16 unk2A6;
    u8 pad2A8[0x2AC - 0x2A8];
    f32 waterLevel;
    f32 unk2B0;
    f32 unk2B4; /* collectable.c reads an s16 pair at 2B4/2B6 - launder those */
    f32 lookDirX; /* look/aim direction: yaw = getAngle(-X,-Z), pitch = getAngle(Y, hyp(X,Z)) */
    f32 lookDirY;
    f32 lookDirZ;
    u8 pad2C4[0x2D0 - 0x2C4];
    f32 freezeEffectTimer; /* counts down by timeDelta while frozen; resets when the shatter effect fires */
    f32 freezeStunTimer;
    f32 freezeRecoverTimer;
    u32 flags2DC; /* flag word */
    u32 flags2E0; /* flag word tested alongside flags2DC (bits 0x100/0x800/0x1000) */
    u32 controlFlags; /* TRICKY_CONTROL_FLAG_* (collectable.c macro set) */
    u32 flags2E8; /* control/state flag word (bits 1/4/0x10/0x20/0x200/0x208) */
    u8 pad2EC[0x2EF - 0x2EC];
    u8 actionId; /* current action/move selector (0..5); compared against prevActionId to detect change */
    u8 prevActionId; /* previous frame's actionId */
    u8 flags2F1; /* bit flags (0x8/0x10/0x80) gating the spawn/anim paths */
    u8 pad2F2[0x2F5 - 0x2F2];
    u8 spawnBits;
    u8 pad2F6[0x2F8 - 0x2F6];
    u16 animEventMask; /* per-frame bitmask OR'd from (1 << anim event index); fed to objAudioFn */
    u8 pad2FA[0x300 - 0x2FA];
    f32 gravity; /* fall acceleration: velocityY -= gravity*dt, posY -= K*gravity*dt^2 */
    f32 base;
    f32 animPlaySpeed;
    f32 currentMoveProgress;
    f32 unk310;
    f32 moveSpeedScale0; /* animPlaySpeed = K / (K2 * scale) for moveId0 */
    f32 moveSpeedScale1; /* paired with moveId1 */
    f32 moveSpeedScale2; /* paired with moveId2 */
    u8 moveId0; /* ObjAnim_SetCurrentMove move id */
    u8 moveId1;
    u8 moveId2;
    u8 flags323; /* anim-active bit flags (0x1/0x2/0x4/0x8) */
    u8 pad324[0x353 - 0x324];
    u8 unk353;
    u8 pad354[0x358 - 0x354];
    s8 unk358;
    u8 pad359[0x360 - 0x359];
    void *lastContactObj;
    f32 contactTimer;
    int light; /* object link */
    int modelChain; /* ObjModelChain handle toggled via ObjModelChain_SetEnabled */
    f32 hitCooldown;
    u8 unk374;
    u8 pad375[0x378 - 0x375];
    u8 unk378;
    u8 pad379[0x37C - 0x379];
    f32 unk37C;
    f32 unk380;
    f32 unk384;
    u8 pad388[0x3D8 - 0x388];
    f32 sparkPos0X; /* spark particle emit point 0 (skeetla_spawnLinkedSparks args.xyz) */
    f32 sparkPos0Y;
    f32 sparkPos0Z;
    f32 sparkPos1X; /* spark particle emit point 1 */
    f32 sparkPos1Y;
    f32 sparkPos1Z;
    u8 pad3F0[0x408 - 0x3F0];
    f32 renderPosX; /* copied to a child object's localPos during Tricky_render */
    f32 renderPosY;
    f32 renderPosZ;
    u8 pad414[0x418 - 0x414];
    void *routeSeedNode; /* candidate route node chosen before seeding route */
    u8 routeSeedDir;
    u8 pad41D[0x420 - 0x41D];
    RomCurveWalker route;
    u8 unk528;
    u8 pad529[3];
    void *unk52C;
    u16 unk530;
    u16 unk532;
    u16 unk534; /* mirrored from unk532 (dll_DF) */
    u8 unk536;
    u8 pad537[1];
    u8 voxBlocks[9][0x30]; /* trickyVoxAllocFn_8004b5d4 records, 0x538..0x6E8 */
    void *unk6E8; /* one u32-spelled site launders */
    int unk6EC;
    f32 *previousPathPoint;
    f32 previousPathX;
    f32 previousPathY;
    f32 previousPathZ;
    u8 *unk700;
    u8 *unk704;
    u8 *unk708;
    u8 *unk70C;
    f32 unk710;
    u8 pad714[0x71C - 0x714];
    f32 unk71C;
    f32 unk720;
    void *unk724;
    u8 unk728;
    u8 pad729[0x72C - 0x729];
    f32 unk72C;
    u32 unk730;
    f32 unk734;
    f32 unk738;
    f32 unk73C;
    f32 unk740;
    u8 pad744[0x798 - 0x744];
    u8 unk798;
    u8 pad799[0x79C - 0x799];
    f32 unk79C;
    f32 unk7A0f;
    f32 unk7A4;
    u8 *unk7A8;
    u8 pad7AC[0x7B0 - 0x7AC];
    u8 *unk7B0;
    u8 pad7B4[0x7B8 - 0x7B4];
    u8 *child;
    u8 pad7BC[0x7C0 - 0x7BC];
    f32 unk7C0;
    f32 unk7C4;
    f32 unk7C8;
    void *unk7CC;
    u8 pad7D0[0x7D4 - 0x7D0];
    u8 *unk7D4;
    u8 pad7D8[0x808 - 0x7D8];
    f32 unk808;
    f32 unk80C;
    f32 unk810;
    f32 unk814;
    u8 pad818[2];
    s16 rotRate;
    u8 pad81C[0x82C - 0x81C];
    u8 modelVariant; /* progress/10; indexes model bank color */
    u8 unk82D;
    u8 unk82E; /* bit flags 5/6/7 (collectable.c overlays) */
    u8 pad82F[0x838 - 0x82F];
    f32 unk838;
    u8 pad83C[0x840 - 0x83C];
} TrickyState;

STATIC_ASSERT(sizeof(TrickyState) == 0x840);
STATIC_ASSERT(offsetof(TrickyState, stateFlags) == 0x54);
STATIC_ASSERT(offsetof(TrickyState, pathRotY) == 0x290);
STATIC_ASSERT(offsetof(TrickyState, routeSeedNode) == 0x418);
STATIC_ASSERT(offsetof(TrickyState, route) == 0x420);
STATIC_ASSERT(offsetof(TrickyState, route.reverse) == 0x4A0);
STATIC_ASSERT(offsetof(TrickyState, lastContactObj) == 0x360);
STATIC_ASSERT(offsetof(TrickyState, hitCooldown) == 0x370);
STATIC_ASSERT(offsetof(TrickyState, previousPathPoint) == 0x6F0);

#endif /* MAIN_DLL_TRICKY_STATE_H_ */
