#ifndef MAIN_DLL_DIM_DLL_01E7_DIMBOSSFIRE_H_
#define MAIN_DLL_DIM_DLL_01E7_DIMBOSSFIRE_H_

#include "main/game_object.h"
#include "types.h"

int dimbossfire_getExtraSize(void);
int dimbossfire_getObjectTypeId(void);
void dimbossfire_free(GameObject* obj);
void dimbossfire_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dimbossfire_hitDetect(void);
void dimbossfire_update(GameObject* obj);
void dimbossfire_init(GameObject* obj, u32 arg2, int placement);
void dimbossfire_release(void);
void dimbossfire_initialise(void);

#endif /* MAIN_DLL_DIM_DLL_01E7_DIMBOSSFIRE_H_ */
