#ifndef MAIN_DLL_DLL_00E3_FIREBALL_API_H_
#define MAIN_DLL_DLL_00E3_FIREBALL_API_H_

#include "main/objanim_update.h"

int Fireball_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate);
void Fireball_free(int* obj);
int Fireball_getExtraSize(void);
int Fireball_getObjectTypeId(void);
void Fireball_hitDetect(int* obj);
void Fireball_init(int* obj);
void Fireball_initialise(void);
void Fireball_release(void);
void Fireball_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void Fireball_update(int* obj);
u8 fn_8016F16C(int* obj);

#endif /* MAIN_DLL_DLL_00E3_FIREBALL_API_H_ */
