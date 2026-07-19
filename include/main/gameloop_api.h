#ifndef MAIN_GAMELOOP_API_H_
#define MAIN_GAMELOOP_API_H_

#include "types.h"
#include "main/gameloop_gamebit_api.h"
#include "main/hud_visibility_api.h"

extern u8 lbl_803DB424;

int getGameState(void);
int getScreenBlankFrameCount(void);
int return1_800202BC(void);
void requestGalleonBattleMusic(void);
void checkReset(void);
void setShouldResetNextFrame(int reset);
void mapReload(void);
void mapLoadByCoords(f32 x, f32 y, f32 z, int act);
void setGameState(int state);
void cutsceneExit(void);
void cutsceneEnterExit(int entering, int affectSounds);
void cutsceneFadeInOut(int mode);
void setTimeStop(int frames);
void doNothing_onSaveSelectScreenExit(void);
void requestKrazoaShrineMusic(void);
int getButtonObjects(int** objectsOut);
int cacheAllocAndCopy(u32 srcAddress, u32 size, u32* cacheCursor, u32* outEnd, u32 limit);
void doNothing_8001F678(int a, int b);
void crash(int a, int b, int c, int d, int e, int f, int g, int h);

void addButtonObject(void* obj);

void removeButtonObject(u32 object);

void blankScreen(int frames);

#endif /* MAIN_GAMELOOP_API_H_ */
