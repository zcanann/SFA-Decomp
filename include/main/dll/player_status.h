#ifndef MAIN_DLL_PLAYER_STATUS_H_
#define MAIN_DLL_PLAYER_STATUS_H_

int playerGetCurMagic(int playerObj);
int playerGetMaxMagic(int playerObj);
int playerGetMaxHealth(int playerObj);
int playerGetCurHealth(int playerObj);

static inline int Player_GetCurrentMagic(int playerObj)
{
    return playerGetCurMagic(playerObj);
}

static inline int Player_GetMaxMagic(int playerObj)
{
    return playerGetMaxMagic(playerObj);
}

static inline int Player_GetMaxHealth(int playerObj)
{
    return playerGetMaxHealth(playerObj);
}

static inline int Player_GetCurrentHealth(int playerObj)
{
    return playerGetCurHealth(playerObj);
}

#endif
