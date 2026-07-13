#ifndef MAIN_GAMELOOP_API_H_
#define MAIN_GAMELOOP_API_H_

#include "types.h"

int gameBitDecrement(int bit);
int gameBitIncrement(int bit);
int getGameState(void);
int getHudHiddenFrameCount(void);
void checkReset(void);
void cutsceneEnterExit(int entering, int affectSounds);
void cutsceneFadeInOut(int mode);
void setTimeStop(int frames);

#endif /* MAIN_GAMELOOP_API_H_ */
