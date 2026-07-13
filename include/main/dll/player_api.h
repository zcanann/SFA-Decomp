#ifndef MAIN_DLL_PLAYER_API_H_
#define MAIN_DLL_PLAYER_API_H_

#include "main/game_object.h"

int objFn_802962b4(GameObject* obj);
int objGetAnimState80A(GameObject* obj);
u8 fn_80296414(GameObject* player, GameObject* otherObj, u8* outDirection);
int fn_802969F0(GameObject* player);
void fn_80296A9C(GameObject* player, int delta);
GameObject* playerGetFocusObject(GameObject* player);
int playerGetMoney(void* player);
void playerAddMoney(GameObject* obj, int amount);
void playerAddHealth(GameObject* obj, int amount);
void objSetAnimStateFlags(GameObject* obj, int flag, int set);

#endif /* MAIN_DLL_PLAYER_API_H_ */
