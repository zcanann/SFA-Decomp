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

#endif /* MAIN_DLL_PLAYER_DATA_H_ */
