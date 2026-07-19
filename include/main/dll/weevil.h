#ifndef H_MAIN_DLL_WEEVIL_H
#define H_MAIN_DLL_WEEVIL_H

#include "main/game_object.h"

void weevil_updateIdle(GameObject* obj, int state);
void weevil_updateEngaged(int obj, int state);
void weevil_init(int unused, u8* state);

#endif /* H_MAIN_DLL_WEEVIL_H */
