#ifndef MAIN_DLL_SB_DLL_01EB_SBSHIPMAST_H_
#define MAIN_DLL_SB_DLL_01EB_SBSHIPMAST_H_

#include "main/game_object.h"

int SB_ShipMast_getExtraSize(void);
int SB_ShipMast_getObjectTypeId(void);
void SB_ShipMast_free(void);
void SB_ShipMast_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void SB_ShipMast_hitDetect(void);
void SB_ShipMast_update(GameObject* obj);
void SB_ShipMast_init(void);
void SB_ShipMast_release(void);
void SB_ShipMast_initialise(void);

#endif
