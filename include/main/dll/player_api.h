#ifndef MAIN_DLL_PLAYER_API_H_
#define MAIN_DLL_PLAYER_API_H_

#include "main/game_object.h"

int objFn_802962b4(GameObject* obj);
int playerGetMoney(void* player);
void playerAddMoney(GameObject* obj, int amount);

#endif /* MAIN_DLL_PLAYER_API_H_ */
