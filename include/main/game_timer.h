#ifndef MAIN_GAME_TIMER_H_
#define MAIN_GAME_TIMER_H_

#include "global.h"

u8 gameTimerIsRunning(void);
int isGameTimerDisabled(void);
void gameTimerStop(void);
void timerSetToCountUp(void);
void gameTimerInit(s8 flags, int minutes);

#endif /* MAIN_GAME_TIMER_H_ */
