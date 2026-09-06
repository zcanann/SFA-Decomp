#ifndef MAIN_DLL_PLAYER_DATA_H_
#define MAIN_DLL_PLAYER_DATA_H_

#include "main/dll/dll_005A_staffcollision.h"
#include "main/dll/dll_000F_unk.h"
#include "main/dll/partfx_interface.h"
#include "game/objects/object.h"
#include "main/lightmap_api.h"
#include "main/shader_api.h"
#include "main/model.h"

typedef struct PlayerModelChainEntry {
    int* modelIds;
    int count;
} PlayerModelChainEntry;

extern GameObject* gPlayerPathObject;
extern u8 gPlayerModelChainStyle;
extern GameObject* gPlayerSpawnedObjects[];
extern StaffCollisionInterface** gPlayerResource;
extern int gPlayerPendingHealth;
extern GameObject* gPlayerStaffObject;
typedef struct PlayerLightfootMoveSpeeds {
    f32 speeds[7];
    u16 challengeGameBits[8];
    f32 challengeMeterScales[8];
} PlayerLightfootMoveSpeeds;
STATIC_ASSERT(sizeof(PlayerLightfootMoveSpeeds) == 0x4C);

extern s16 gPlayerMoveTableC[];
extern PlayerLightfootMoveSpeeds gPlayerMoveSpeedTable;
extern s16 gPlayerCurrentMoveId;
extern s16 gPlayerPrevMoveId;
extern u16 gPlayerHeldButtonMask;
extern int gPlayerEggObject;
extern int gPlayerModelChain;
extern int gPlayerSfxTimerA;
extern int gPlayerSfxTimerB;
extern int gPlayerSfxTimerC;
extern int gPlayerSfxTimerD;
extern int gPlayerStepSfxTimer;
extern s16 gPlayerSelectedItem;
extern int gPlayerStateHandlers[];
extern void* gPlayerDefaultStateHandler;
extern void* gPlayerChildObject;
extern PlayerModelChainEntry* gPlayerModelChainConfig;
extern Shader* gPlayerKrazoaShader;
extern PartFxSpawnParams gPlayerPartFxParams;
extern LightmapVertex gPlayerHudVtxBuf[8];
extern s16 gPlayerStopMoves[4];
extern u8 gPlayerSurfacePfxModeTable[];
extern u64 gPlayerLastSfxFrame;
extern u64 gPlayerFrameCounter;

typedef struct PlayerMoveSlot {
    u8 slotId;
    u8 unk01;
    s16 moveTableIndex;
    s16 unk04;
    s16 unk06;
    int hitWindowFlags[3];
    u8 hitVolumeId;
    s8 nextMoveSlots[5];
    u8 unk1A[2];
    f32 moveSpeed;
    f32 comboWindowOpen;
    f32 comboWindowClose;
    f32 attackLandProgress;
    f32 transitionProgress;
    f32 hitWindowStart[3];
    f32 hitWindowEnd[3];
    f32 swipeStart;
    f32 swipeLengthScale;
    f32 sfxProgressA;
    f32 sfxProgressB;
    f32 unk58;
    u8 unk5C;
    s8 hitWindowType[3];
    ObjWeaponDaTable weaponDa;
    f32 animSpeed;
    u8 chainBreakFlag;
    u8 unk6D[3];
    f32 hitWindowUnk70[3];
    f32 hitWindowUnk7C[3];
    u8 flags88;
    u8 unk89[3];
    f32 unk8C;
    s8 unk90;
    u8 unk91[3];
    f32 hitWindowUnk94[3];
    f32 unkA0;
    f32 unkA4;
    u8 hitInterval[3]; /* 0xA8: per-hit-window repeat-hit interval, copied into PlayerState.hitInterval */
    u8 hitCountMax[3]; /* 0xAB: per-hit-window max hit count, copied into PlayerState.hitCountMax */
    u8 padAE[2];
} PlayerMoveSlot;

STATIC_ASSERT(sizeof(PlayerMoveSlot) == 0xb0);
STATIC_ASSERT(offsetof(PlayerMoveSlot, hitInterval) == 0xA8);
STATIC_ASSERT(offsetof(PlayerMoveSlot, hitCountMax) == 0xAB);
STATIC_ASSERT(offsetof(PlayerMoveSlot, moveTableIndex) == 0x02);
STATIC_ASSERT(offsetof(PlayerMoveSlot, hitWindowFlags) == 0x08);
STATIC_ASSERT(offsetof(PlayerMoveSlot, hitVolumeId) == 0x14);
STATIC_ASSERT(offsetof(PlayerMoveSlot, nextMoveSlots) == 0x15);
STATIC_ASSERT(offsetof(PlayerMoveSlot, moveSpeed) == 0x1c);
STATIC_ASSERT(offsetof(PlayerMoveSlot, comboWindowOpen) == 0x20);
STATIC_ASSERT(offsetof(PlayerMoveSlot, comboWindowClose) == 0x24);
STATIC_ASSERT(offsetof(PlayerMoveSlot, attackLandProgress) == 0x28);
STATIC_ASSERT(offsetof(PlayerMoveSlot, transitionProgress) == 0x2c);
STATIC_ASSERT(offsetof(PlayerMoveSlot, hitWindowStart) == 0x30);
STATIC_ASSERT(offsetof(PlayerMoveSlot, hitWindowEnd) == 0x3c);
STATIC_ASSERT(offsetof(PlayerMoveSlot, swipeStart) == 0x48);
STATIC_ASSERT(offsetof(PlayerMoveSlot, swipeLengthScale) == 0x4C);
STATIC_ASSERT(offsetof(PlayerMoveSlot, sfxProgressA) == 0x50);
STATIC_ASSERT(offsetof(PlayerMoveSlot, sfxProgressB) == 0x54);
STATIC_ASSERT(offsetof(PlayerMoveSlot, hitWindowType) == 0x5d);
STATIC_ASSERT(offsetof(PlayerMoveSlot, weaponDa) == 0x60);
STATIC_ASSERT(offsetof(PlayerMoveSlot, animSpeed) == 0x68);
STATIC_ASSERT(offsetof(PlayerMoveSlot, chainBreakFlag) == 0x6c);
STATIC_ASSERT(offsetof(PlayerMoveSlot, hitWindowUnk70) == 0x70);
STATIC_ASSERT(offsetof(PlayerMoveSlot, hitWindowUnk7C) == 0x7c);
STATIC_ASSERT(offsetof(PlayerMoveSlot, flags88) == 0x88);
STATIC_ASSERT(offsetof(PlayerMoveSlot, hitWindowUnk94) == 0x94);
STATIC_ASSERT(offsetof(PlayerMoveSlot, unkA0) == 0xa0);
STATIC_ASSERT(offsetof(PlayerMoveSlot, unkA4) == 0xa4);

extern PlayerMoveSlot gPlayerMoveSlotData[28];
typedef struct PlayerAnimSpeedTuning {
    f32 gaitSpeedThresholds[6];
    f32 bodyCollisionPoints[2][3];
    f32 groundCollisionPoint[3];
    int mountableObjectIds[9];
    int rideableObjectIds[4];
    f32 foxStopMoveSpeeds[4];
    f32 krystalStopMoveSpeeds[4];
} PlayerAnimSpeedTuning;

STATIC_ASSERT(sizeof(PlayerAnimSpeedTuning) == 0x90);
STATIC_ASSERT(offsetof(PlayerAnimSpeedTuning, bodyCollisionPoints) == 0x18);
STATIC_ASSERT(offsetof(PlayerAnimSpeedTuning, groundCollisionPoint) == 0x30);
STATIC_ASSERT(offsetof(PlayerAnimSpeedTuning, mountableObjectIds) == 0x3c);
STATIC_ASSERT(offsetof(PlayerAnimSpeedTuning, rideableObjectIds) == 0x60);
STATIC_ASSERT(offsetof(PlayerAnimSpeedTuning, foxStopMoveSpeeds) == 0x70);
STATIC_ASSERT(offsetof(PlayerAnimSpeedTuning, krystalStopMoveSpeeds) == 0x80);

extern PlayerAnimSpeedTuning gPlayerAnimSpeedThresholds;
extern s16 gPlayerMoveTableA[96];
extern s16 gPlayerSpellGameBits[52];
extern s16 gPlayerMoveTableB[14];
extern s16 gPlayerMoveSlotTable[44];
extern GameObject* gPlayerInteractTarget;

extern int lbl_80332EC0[];
extern s16 lbl_80332EF0[];
extern s16 lbl_80332F2C[];
extern s16 lbl_80332F48[];
extern s16 lbl_80332F78[];
extern s16 lbl_80332F88[];
extern s16 lbl_80333110[];
extern f32 gPlayerDefaultMoveParams[24];
typedef struct PlayerMotionTuning {
    s16 moveSequences[4][12];
    f32 velSmoothRateCurve[41];
    f32 targetYawSmoothRateCurve[41];
    f32 targetYawRateLimitCurve[46];
    f32 yawSmoothRateCurve[41];
    f32 yawRateLimitCurve[46];
} PlayerMotionTuning;

STATIC_ASSERT(sizeof(PlayerMotionTuning) == 0x3bc);
STATIC_ASSERT(offsetof(PlayerMotionTuning, velSmoothRateCurve) == 0x60);
STATIC_ASSERT(offsetof(PlayerMotionTuning, targetYawSmoothRateCurve) == 0x104);
STATIC_ASSERT(offsetof(PlayerMotionTuning, targetYawRateLimitCurve) == 0x1a8);
STATIC_ASSERT(offsetof(PlayerMotionTuning, yawSmoothRateCurve) == 0x260);
STATIC_ASSERT(offsetof(PlayerMotionTuning, yawRateLimitCurve) == 0x304);

extern PlayerMotionTuning gPlayerMotionTuning;
extern s16 lbl_8033366C[];
extern f32 lbl_8033369C[];
extern f32 gPlayerMoveRootHeights[];
extern f32 gPlayerModelChainOriginX;
extern f32 gPlayerModelChainOriginY;
extern f32 gPlayerModelChainOriginZ;
extern f32 lbl_803DC67C;
extern f32 lbl_803DC680;
extern f32 lbl_803DC684;
extern int lbl_803DC688[2];
extern f32 lbl_803DC690[2];
extern s16 gPlayerClimbOntoWallMoves[2];
extern s16 gPlayerClimbOntoWallAltMoves[2];
extern u8 lbl_803DC6A4[4];
extern f32 lbl_803DC6B8[2];
extern f32 lbl_803DC6C0;
extern int lbl_803DC6C4[2];
extern f32 lbl_803DC6D4;
extern f32 lbl_803DC6D8;
extern f32 lbl_803DC6DC;
extern f32 lbl_803DC6E0;
extern f32 lbl_803DC6E4;
extern u8 gPlayerIceSpellSustaining;
extern f32 lbl_803DE430;
extern f32 gPlayerClimbStartY;
extern f32 gPlayerClimbEndY;
extern f32 gPlayerSinkSfxTimer;
extern u8 lbl_803DE458;
extern u8 gPlayerHitReactionVariant;
extern f32 gPlayerFireLaserCountdown;
extern f32 gPlayerStaffSfxTimer;
extern f32 lbl_803DE464;
extern f32 gPlayerSeqWalkPrevDist;
extern s8 gPlayerSeqWalkStallFrames;
extern f32 gPlayerTeleportAnimRearm;
extern f32 gPlayerLiftRockPullAccum;
extern u8 gPlayerRocketBoostSfxPlayed;
extern u8 gPlayerQuakeChargeSfxPlayed;
extern f32 gPlayerStaffBoostTargetY;
extern f32 gPlayerStaffBoostStartY;
extern f32 gPlayerLadderSlideVel;
extern s16 lbl_803DE4B0;

extern const u8 lbl_802C2B30[][16];

#endif /* MAIN_DLL_PLAYER_DATA_H_ */
