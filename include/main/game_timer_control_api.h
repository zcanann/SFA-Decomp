#ifndef MAIN_GAME_TIMER_CONTROL_API_H_
#define MAIN_GAME_TIMER_CONTROL_API_H_

#include "types.h"

int isGameTimerDisabled(void);
void gameTimerStop(void);
void timerSetToCountUp(void);
void gameTimerInit(s8 flags, int minutes);

#endif /* MAIN_GAME_TIMER_CONTROL_API_H_ */
