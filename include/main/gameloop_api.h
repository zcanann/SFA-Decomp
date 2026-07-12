#ifndef MAIN_GAMELOOP_API_H_
#define MAIN_GAMELOOP_API_H_

#include "types.h"

int gameBitDecrement(int bit);
int gameBitIncrement(int bit);
int getHudHiddenFrameCount(void);
void checkReset(void);
void cutsceneFadeInOut(int mode);
void setTimeStop(int frames);

#endif /* MAIN_GAMELOOP_API_H_ */
