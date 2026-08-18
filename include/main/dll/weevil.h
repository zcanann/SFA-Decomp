#ifndef H_MAIN_DLL_WEEVIL_H
#define H_MAIN_DLL_WEEVIL_H

#include "game/objects/object.h"

void weevil_updateIdle(GameObject* obj, void* state);
void weevil_updateEngaged(GameObject* obj, void* state);
void weevil_init(GameObject* unused, u8* state);

#endif /* H_MAIN_DLL_WEEVIL_H */
