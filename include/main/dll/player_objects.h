#ifndef MAIN_DLL_PLAYER_OBJECTS_H_
#define MAIN_DLL_PLAYER_OBJECTS_H_

#include "main/game_object.h"
int objGetFirstChild(int playerObj);
int playerGetHeldObject(GameObject* playerObj, int* out);

static inline int Player_GetStaffObject(int playerObj)
{
    return objGetFirstChild(playerObj);
}

static inline int Player_GetHeldObject(int playerObj, int* out)
{
    return playerGetHeldObject((GameObject*)(playerObj), out);
}

#endif
