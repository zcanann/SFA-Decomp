#ifndef MAIN_DLL_PLAYER_DATA_H_
#define MAIN_DLL_PLAYER_DATA_H_

#include "main/game_object.h"

extern void* gPlayerPathObject;
extern u8 gPlayerSubState;
extern void* gPlayerSpawnedObjects[];
extern void* gPlayerResource;
extern int gPlayerPendingHealth;
extern f32 gPlayerDegToBinAngle;
extern GameObject* gPlayerStaffObject;
extern s16 gPlayerMoveTableC[];
extern f32 gPlayerMoveSpeedTable[];
extern s16 gPlayerCurrentMoveId;
extern s16 gPlayerPrevMoveId;
extern u16 gPlayerHeldButtonMask;
extern f32 gPlayerPi;
extern f32 gPlayerPi2;
extern int gPlayerEggObject;
extern int gPlayerModelChain;
extern int gPlayerSfxTimerA;
extern int gPlayerSfxTimerB;
extern int gPlayerSfxTimerC;
extern int gPlayerSfxTimerD;
extern int gPlayerStepSfxTimer;
extern s16 gPlayerSelectedItem;
extern int gPlayerStateHandlers[];
extern int gPlayerDefaultStateHandler;
extern void* gPlayerChildObject;
extern int gPlayerModelChainConfig;
extern int gPlayerHeldObject;
extern f32 gPlayerPartFxParams[];
extern u8 gPlayerHudVtxBuf[];
extern s16 gPlayerStopMoves[4];
extern int* gPlayerShadowInterface;
extern u8 gPlayerSurfacePfxModeTable[];
extern u64 gPlayerLastSfxFrame;
extern u64 gPlayerFrameCounter;

extern s16 gPlayerMoveSlotData[2464];
extern f32 gPlayerAnimSpeedThresholds[36];
extern int gPlayerMoveTableA[48];
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
extern int lbl_80333250[];
extern s16 lbl_803332B0[];
extern s16 lbl_8033366C[];
extern f32 lbl_8033369C[];
extern f32 lbl_803DAF88[];
extern u8 lbl_803DE42C;
extern f32 lbl_803DE430;
extern f32 lbl_803DE438;
extern f32 lbl_803DE43C;
extern f32 lbl_803DE440;
extern u8 lbl_803DE458;
extern u8 lbl_803DE459;
extern f32 lbl_803DE45C;
extern f32 lbl_803DE460;
extern f32 lbl_803DE464;
extern f32 lbl_803DE468;
extern s8 lbl_803DE46C;
extern f32 lbl_803DE478;
extern f32 lbl_803DE488;
extern u8 lbl_803DE48C;
extern u8 lbl_803DE48D;
extern f32 lbl_803DE490;
extern f32 lbl_803DE494;
extern f32 lbl_803DE498;
extern s16 lbl_803DE4B0;

#endif /* MAIN_DLL_PLAYER_DATA_H_ */
