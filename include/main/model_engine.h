#ifndef MAIN_MODEL_ENGINE_H_
#define MAIN_MODEL_ENGINE_H_

#include "types.h"

int getCurUiDll(void);
int getUiDllFn_80014930(void);
int isGameTimerDisabled(void);
void gameTimerStop(void);
void timerSetToCountUp(void);
void gameTimerInit(s8 flags, int minutes);
void loadUiDll(int index);

#endif /* MAIN_MODEL_ENGINE_H_ */
