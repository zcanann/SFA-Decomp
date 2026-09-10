#ifndef MAIN_GAMELOOP_INTERNAL_H_
#define MAIN_GAMELOOP_INTERNAL_H_

#include "game/objects/object_fwd.h"
#include "types.h"
#include "dolphin/gx/GXStruct.h"

extern int gGameLoopPendingUiDllId;
extern f32 gGameLoopMusicFadeTimer;
extern u8 gGameLoopResetComboDebounce;
extern char sGameLoopResetMessages[0x50];
#if defined(VERSION_GSAE01_rev1) || defined(VERSION_GSAP01) || defined(VERSION_GSAP01_rev1)
extern GXRenderModeObj gGameLoopPalRenderMode;
#endif
extern f32 gGameLoopResetFadeOutTimer;
extern u8* gAskProgressiveScanFlag;
extern int gGameLoopPendingMapId;
extern int gGameLoopPendingMapDataFileId;
extern u8 gGameLoopPendingMusicId;
extern GameObject* gGameLoopButtonObjects[2];
extern u8 gGameLoopProgressiveMode;
extern u8* gGameBitSaveData;
typedef struct GameBitDef {
    u16 firstBit;
    u8 flags;
    u8 taskHintId;
} GameBitDef;

extern GameBitDef* gGameBitTable;
extern s16 gGameBitCount;
extern int gGameLoopPlayerTrailIndex;
extern int gGameLoopPlayerTrailTime;
extern f32 gGameLoopResetHoldTimer;
extern u8 gGameLoopHardReset;
extern u8 gGameLoopMapLoaded;
extern void* gDll12Interface;
extern u8 gGameLoopInitComplete;
extern u8 gGameLoopButtonObjectCount;
extern s16 screenBlankFrameCount;
extern u8 gGameLoopMusicActive;
extern u16 gGameLoopMusicRequestCount;
extern u8 gGameLoopMapLoadPending;
extern u8 gGameLoopFullMapUnloadPending;
extern u8 lbl_803DCA3F;
extern u8 shouldResetNextFrame;
extern u8 gameState;
extern u8 timeStop;
extern s8 frameCountdown;
extern s8 hudHiddenFrameCount;
extern u8 gGameLoopReloadRequested;
extern u8 lbl_803DCA38;

void init(void);
void askProgressiveScanMode(void);

#endif /* MAIN_GAMELOOP_INTERNAL_H_ */
