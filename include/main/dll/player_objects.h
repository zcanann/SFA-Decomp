#ifndef MAIN_DLL_PLAYER_OBJECTS_H_
#define MAIN_DLL_PLAYER_OBJECTS_H_

int fn_802966CC(int playerObj);
int fn_802966D4(int playerObj, int *out);

static inline int Player_GetStaffObject(int playerObj)
{
    return fn_802966CC(playerObj);
}

static inline int Player_GetHeldObject(int playerObj, int *out)
{
    return fn_802966D4(playerObj, out);
}

#endif
