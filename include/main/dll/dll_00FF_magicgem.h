#ifndef MAIN_DLL_DLL_00FF_MAGICGEM_H_
#define MAIN_DLL_DLL_00FF_MAGICGEM_H_

#include "main/game_object.h"

typedef struct MagicgemObjectDef MagicgemObjectDef;

int MagicDust_getExtraSize(void);
void MagicDust_free(GameObject* obj);
void MagicDust_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void MagicDust_update(GameObject* obj);
void MagicDust_init(GameObject* obj, MagicgemObjectDef* placement);

#endif /* MAIN_DLL_DLL_00FF_MAGICGEM_H_ */
