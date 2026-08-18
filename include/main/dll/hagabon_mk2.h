#ifndef MAIN_DLL_HAGABON_MK2_H_
#define MAIN_DLL_HAGABON_MK2_H_

#include "game/objects/object.h"

void crawler_rotateVectorYaw(int unused1, int* unused2, f32* vec, int unused3, int nodeIndex, f32 phase);
void hagabonMK2_stopLoopSfx(GameObject* obj, u8* state);
void hagabonMK2_updateB(GameObject* obj, u8* state);
void hagabonMK2_update(GameObject* obj, u8* state);
void hagabonMK2_init(GameObject* obj, struct EnemyState* st);

#endif /* MAIN_DLL_HAGABON_MK2_H_ */
