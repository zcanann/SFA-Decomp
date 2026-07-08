#ifndef MAIN_DLL_DLL_00F6_AREA_H_
#define MAIN_DLL_DLL_00F6_AREA_H_

#include "main/game_object.h"

int area_getExtraSize(void);
int area_getObjectTypeId(void);
void area_free(void);
void area_render(void);
void area_hitDetect(void);
void area_update(void);
void area_init(GameObject* obj);
void area_release(void);
void area_initialise(void);

#endif /* MAIN_DLL_DLL_00F6_AREA_H_ */
