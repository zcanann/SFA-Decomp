#ifndef MAIN_DLL_PLAYER_STATUS_H_
#define MAIN_DLL_PLAYER_STATUS_H_

int fn_80296A14(int playerObj);
int fn_80296A8C(int playerObj);
int fn_80296AD4(int playerObj);
int fn_80296AE8(int playerObj);

static inline int Player_GetCurrentMagic(int playerObj)
{
    return fn_80296A14(playerObj);
}

static inline int Player_GetMaxMagic(int playerObj)
{
    return fn_80296A8C(playerObj);
}

static inline int Player_GetMaxHealth(int playerObj)
{
    return fn_80296AD4(playerObj);
}

static inline int Player_GetCurrentHealth(int playerObj)
{
    return fn_80296AE8(playerObj);
}

#endif
