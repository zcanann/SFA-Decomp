#ifndef MAIN_DLL_DLL_01B5_LIGHTFOOT_H_
#define MAIN_DLL_DLL_01B5_LIGHTFOOT_H_

#include "main/game_object.h"

int lightfoot_getExtraSize(void);
int lightfoot_getObjectTypeId(void);
void lightfoot_free(GameObject* obj, int flag);
void lightfoot_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void lightfoot_hitDetect(void);
void lightfoot_update(GameObject* obj);
void lightfoot_init(GameObject* obj, int def, int flag);
void lightfoot_release(void);
void lightfoot_initialise(void);

#endif /* MAIN_DLL_DLL_01B5_LIGHTFOOT_H_ */
