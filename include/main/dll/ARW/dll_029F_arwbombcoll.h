#ifndef MAIN_DLL_ARW_DLL_029F_ARWBOMBCOLL_H
#define MAIN_DLL_ARW_DLL_029F_ARWBOMBCOLL_H

#include "main/game_object.h"

typedef struct RingState RingState;

void arwbombcoll_updateMovingAxis(GameObject* obj, RingState* state);
void Ring_onCollect(GameObject* obj, RingState* state, int arwing);
int arwbombcoll_checkArwingCollision(GameObject* obj, RingState* state, int arwing);

#endif
