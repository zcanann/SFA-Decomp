#ifndef H_MAIN_DLL_HOODEDZYCK_H
#define H_MAIN_DLL_HOODEDZYCK_H

#include "main/game_object.h"

void hoodedZyck_updateIdle(GameObject* obj, int state);
void hoodedZyck_updateB(s16* obj, u8* state);
void hoodedZyck_update(s16* obj, u8* state);
void hoodedZyck_init(int* obj, int* st);

#endif /* H_MAIN_DLL_HOODEDZYCK_H */
