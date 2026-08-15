#ifndef MAIN_DLL_PLAYER_TARGET_H_
#define MAIN_DLL_PLAYER_TARGET_H_

#include "game/objects/object.h"
GameObject* playerGetTargetObject(GameObject* playerObj);

static inline int Player_GetTargetObject(int playerObj)
{
    return (int)playerGetTargetObject((GameObject*)(playerObj));
}

#endif
