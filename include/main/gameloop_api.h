#ifndef MAIN_GAMELOOP_API_H_
#define MAIN_GAMELOOP_API_H_

#include "types.h"
#include "main/gameloop_gamebit_api.h"
#include "main/hud_visibility_api.h"

int getGameState(void);
void fn_8001FE90(void);
void checkReset(void);
void cutsceneExit(void);
void cutsceneEnterExit(int entering, int affectSounds);
void cutsceneFadeInOut(int mode);
void setTimeStop(int frames);
void doNothing_onSaveSelectScreenExit(void);
void fn_8001FEA8(void);

#endif /* MAIN_GAMELOOP_API_H_ */
