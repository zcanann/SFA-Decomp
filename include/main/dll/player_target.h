#ifndef MAIN_DLL_PLAYER_TARGET_H_
#define MAIN_DLL_PLAYER_TARGET_H_

int fn_80296118(int playerObj);

static inline int Player_GetTargetObject(int playerObj)
{
    return fn_80296118(playerObj);
}

#endif
