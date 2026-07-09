#ifndef MAIN_DLL_PLAYER_OBJECTS_H_
#define MAIN_DLL_PLAYER_OBJECTS_H_

int objGetFirstChild(int playerObj);
int playerGetHeldObject(struct GameObject *playerObj, int *out);

static inline int Player_GetStaffObject(int playerObj)
{
    return objGetFirstChild(playerObj);
}

static inline int Player_GetHeldObject(int playerObj, int *out)
{
    return playerGetHeldObject((struct GameObject*)(playerObj), out);
}

#endif
