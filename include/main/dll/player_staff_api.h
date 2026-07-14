#ifndef MAIN_DLL_PLAYER_STAFF_API_H_
#define MAIN_DLL_PLAYER_STAFF_API_H_

#include "main/game_object.h"

void staffToggle(GameObject* obj, int enabled);
void playerPullOutStaff(GameObject* obj, int mode);
void playerPutAwayStaff(GameObject* obj, int mode);

#endif /* MAIN_DLL_PLAYER_STAFF_API_H_ */
