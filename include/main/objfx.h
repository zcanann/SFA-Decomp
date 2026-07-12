#ifndef MAIN_OBJFX_H_
#define MAIN_OBJFX_H_

#include "global.h"

void objLightFn_8009a1dc(void *obj, f32 scale, void *origin, u8 type, void *light);
void objfx_spawnRandomBurst(void* obj, u8 type, u8 count, void* origin, u8 flagByte, f32 mult);
void objfx_spawnMaskedHitEffect(void* obj, u8 type, u8 mode, u8 mask, void* origin, f32 scale);

void objfx_spawnHitEmitterAtPos(f32* pos, u8 a, u8 b, u8 c, u8 d);

#endif /* MAIN_OBJFX_H_ */
