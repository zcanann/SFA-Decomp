#ifndef MAIN_DLL_SB_DLL_01EE_SBCANNONBALL_H_
#define MAIN_DLL_SB_DLL_01EE_SBCANNONBALL_H_

#include "main/game_object.h"

#define SB_CANNONBALL_ALIAS_OBJECT_TYPE 0x0113

int SB_CannonBall_getExtraSize(void);
int SB_CannonBall_getObjectTypeId(void);
void SB_CannonBall_free(GameObject* obj);
void SB_CannonBall_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void SB_CannonBall_hitDetect(GameObject* obj);
void SB_CannonBall_update(GameObject* obj);
void SB_CannonBall_init(GameObject* obj);
void SB_CannonBall_release(void);
void SB_CannonBall_initialise(void);

#endif /* MAIN_DLL_SB_DLL_01EE_SBCANNONBALL_H_ */
