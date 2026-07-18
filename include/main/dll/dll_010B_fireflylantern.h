#ifndef MAIN_DLL_DLL_010B_FIREFLYLANTERN_H_
#define MAIN_DLL_DLL_010B_FIREFLYLANTERN_H_

#include "main/game_object.h"

int FireFlyLantern_getExtraSize(void);
int FireFlyLantern_getObjectTypeId(void);
void FireFlyLantern_free(int obj);
void FireFlyLantern_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void FireFlyLantern_update(GameObject* obj);
void FireFlyLantern_init(GameObject* obj, int def);

#endif /* MAIN_DLL_DLL_010B_FIREFLYLANTERN_H_ */
