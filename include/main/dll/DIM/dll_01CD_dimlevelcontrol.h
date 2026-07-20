#ifndef MAIN_DLL_DIM_DLL_01CD_DIMLEVELCONTROL_H_
#define MAIN_DLL_DIM_DLL_01CD_DIMLEVELCONTROL_H_

#include "main/game_object.h"

int dim_levelcontrol_getExtraSize(void);
void dim_levelcontrol_free(GameObject* obj);
void dim_levelcontrol_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void dim_levelcontrol_update(GameObject* obj);
void dim_levelcontrol_init(GameObject* obj);

#endif /* MAIN_DLL_DIM_DLL_01CD_DIMLEVELCONTROL_H_ */
