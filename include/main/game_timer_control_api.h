#ifndef MAIN_GAME_TIMER_CONTROL_API_H_
#define MAIN_GAME_TIMER_CONTROL_API_H_

#include "types.h"

enum GameTimerFlags {
    GAME_TIMER_COUNT_DOWN = 1,
    GAME_TIMER_COUNT_UP = 2,
    GAME_TIMER_LOOP_SOUND = 4,
    GAME_TIMER_END_SOUND = 8,
    GAME_TIMER_DISPLAY = 16
};

int isGameTimerDisabled(void);
void gameTimerStop(void);
/* Clears the pause set by initialization; does not change direction. */
void gameTimerResume(void);
void gameTimerInit(s8 flags, int durationSeconds);

#endif /* MAIN_GAME_TIMER_CONTROL_API_H_ */
