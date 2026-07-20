#ifndef MAIN_DLL_CC_DLL_0187_CCQUEEN_H_
#define MAIN_DLL_CC_DLL_0187_CCQUEEN_H_

#include "global.h"
#include "main/game_object.h"

int ccqueen_getExtraSize(void);
void ccqueen_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void ccqueen_update(GameObject* obj);
void ccqueen_init(GameObject* obj, u8* placement);

#endif /* MAIN_DLL_CC_DLL_0187_CCQUEEN_H_ */
