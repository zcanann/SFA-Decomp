#ifndef MAIN_DLL_DLL_0144_DLL144_H_
#define MAIN_DLL_DLL_0144_DLL144_H_

#include "main/game_object.h"
#include "global.h"
#include "main/objanim_update.h"

int dll_144_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);
int dll_144_getExtraSize(void);
int dll_144_getObjectTypeId(void);
void dll_144_free(void);
void dll_144_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dll_144_hitDetect(void);
void dll_144_update(void);
void dll_144_init(GameObject* obj);
void dll_144_release(void);
void dll_144_initialise(void);

#endif /* MAIN_DLL_DLL_0144_DLL144_H_ */
