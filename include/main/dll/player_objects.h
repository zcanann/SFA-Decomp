#ifndef MAIN_DLL_PLAYER_OBJECTS_H_
#define MAIN_DLL_PLAYER_OBJECTS_H_

#include "main/game_object.h"
GameObject* objGetFirstChild(GameObject* playerObj);
int playerGetHeldObject(GameObject* playerObj, GameObject** outHeldObj);
int playerSetHeldObject(GameObject* playerObj, GameObject* heldObj);

static inline GameObject* Player_GetStaffObject(GameObject* playerObj)
{
    return objGetFirstChild(playerObj);
}

static inline int Player_GetHeldObject(GameObject* playerObj, GameObject** outHeldObj)
{
    return playerGetHeldObject(playerObj, outHeldObj);
}

#endif
