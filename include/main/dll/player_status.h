#ifndef MAIN_DLL_PLAYER_STATUS_H_
#define MAIN_DLL_PLAYER_STATUS_H_

#include "main/game_object.h"
int playerGetCurMagic(GameObject* playerObj);
int playerGetMaxMagic(GameObject* playerObj);
int playerGetMaxHealth(GameObject* playerObj);
int playerGetCurHealth(GameObject* playerObj);
int playerIsDead(GameObject* playerObj);
void playerSetIsDead(GameObject* playerObj, int isDead);

static inline int Player_GetCurrentMagic(int playerObj)
{
    return playerGetCurMagic((GameObject*)playerObj);
}

static inline int Player_GetMaxMagic(int playerObj)
{
    return playerGetMaxMagic((GameObject*)(playerObj));
}

static inline int Player_GetMaxHealth(int playerObj)
{
    return playerGetMaxHealth((GameObject*)(playerObj));
}

static inline int Player_GetCurrentHealth(int playerObj)
{
    return playerGetCurHealth((GameObject*)(playerObj));
}

#endif
