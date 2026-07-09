#ifndef MAIN_DLL_SB_DLL_01EA_SBSHIPHEAD_H_
#define MAIN_DLL_SB_DLL_01EA_SBSHIPHEAD_H_

#include "main/game_object.h"

int SB_ShipHead_getExtraSize(void);
int SB_ShipHead_getObjectTypeId(void);
void SB_ShipHead_free(int obj);
void SB_ShipHead_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void SB_ShipHead_update(int obj);
void SB_ShipHead_init(struct GameObject* obj);

#endif
