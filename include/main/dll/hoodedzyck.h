#ifndef H_MAIN_DLL_HOODEDZYCK_H
#define H_MAIN_DLL_HOODEDZYCK_H

#include "game/objects/object.h"

void hoodedZyck_updateIdle(GameObject* obj, void* state);
void hoodedZyck_updateB(GameObject* obj, u8* state);
void hoodedZyck_update(GameObject* obj, u8* state);
void hoodedZyck_init(GameObject* obj, struct EnemyState* st);

#endif /* H_MAIN_DLL_HOODEDZYCK_H */
