#ifndef MAIN_DLL_DIM_DLL_01CA_DIMEXPLOSION_H_
#define MAIN_DLL_DIM_DLL_01CA_DIMEXPLOSION_H_

#include "main/game_object.h"
#include "types.h"

void explosion_spawnFlame(GameObject* obj, u8 gen, f32 spd, f32 x, f32 y, f32 z);
void explosion_computeColor(f32 age, f32 lifetime, u8 mode, u8* out);
int explosion_getExtraSize(void);
int explosion_getObjectTypeId(GameObject* obj);
void explosion_free(GameObject* obj);
void explosion_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void explosion_hitDetect(void);
void explosion_update(GameObject* obj);
void explosion_init(int obj, int p2);
void explosion_release(u32 obj);
void explosion_initialise(void);

#endif
