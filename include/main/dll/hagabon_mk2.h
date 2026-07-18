#ifndef MAIN_DLL_HAGABON_MK2_H_
#define MAIN_DLL_HAGABON_MK2_H_

#include "main/game_object.h"

void crawler_rotateVectorYaw(int unused1, int unused2, f32* vec, f32 f1, int p5, u32 int_deg);
void hagabonMK2_stopLoopSfx(int obj, u8* state);
void hagabonMK2_updateB(s16* obj, u8* state);
void hagabonMK2_update(s16* obj, u8* state);
void crawler_initTailModel(int* obj, int* st);

#endif /* MAIN_DLL_HAGABON_MK2_H_ */
