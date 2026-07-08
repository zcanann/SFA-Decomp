#ifndef MAIN_DLL_SB_DLL_01ED_SBFIREBALL_H_
#define MAIN_DLL_SB_DLL_01ED_SBFIREBALL_H_

#include "main/game_object.h"

int SB_FireBall_getExtraSize(void);
int SB_FireBall_getObjectTypeId(void);
void SB_FireBall_free(int obj);
void SB_FireBall_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void SB_FireBall_hitDetect(int* obj);
void SB_FireBall_update(GameObject* obj);
void SB_FireBall_init(GameObject* obj);
void SB_FireBall_release(void);
void SB_FireBall_initialise(void);

#endif
