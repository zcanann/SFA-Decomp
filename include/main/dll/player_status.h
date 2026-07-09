#ifndef MAIN_DLL_PLAYER_STATUS_H_
#define MAIN_DLL_PLAYER_STATUS_H_

int playerGetCurMagic(int playerObj);
int playerGetMaxMagic(struct GameObject *playerObj);
int playerGetMaxHealth(struct GameObject *playerObj);
int playerGetCurHealth(struct GameObject *playerObj);

static inline int Player_GetCurrentMagic(int playerObj)
{
    return playerGetCurMagic(playerObj);
}

static inline int Player_GetMaxMagic(int playerObj)
{
    return playerGetMaxMagic((struct GameObject*)(playerObj));
}

static inline int Player_GetMaxHealth(int playerObj)
{
    return playerGetMaxHealth((struct GameObject*)(playerObj));
}

static inline int Player_GetCurrentHealth(int playerObj)
{
    return playerGetCurHealth((struct GameObject*)(playerObj));
}

#endif
