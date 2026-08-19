#ifndef H_MAIN_DLL_KOOSHY_H
#define H_MAIN_DLL_KOOSHY_H

#include "game/objects/object.h"

void kooshy_updateIdle(GameObject* obj, void* state);
void kooshy_updateEngaged(GameObject* obj, void* state);
void kooshy_init(GameObject* unused, void* state);

#endif /* H_MAIN_DLL_KOOSHY_H */
