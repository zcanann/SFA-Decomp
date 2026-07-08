#ifndef MAIN_DLL_DLL_00CD_ICEBALL_H_
#define MAIN_DLL_DLL_00CD_ICEBALL_H_

#include "main/game_object.h"

void fn_8015FBEC(int obj);
void fn_8015FCCC(int obj);
int IceBall_getExtraSize(void);
int IceBall_getObjectTypeId(void);
void IceBall_free(void);
void IceBall_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void IceBall_hitDetect(void);
void IceBall_update(u16* obj, int unused);
void IceBall_init(GameObject* obj);
void IceBall_release(void);
void IceBall_initialise(void);

#endif /* MAIN_DLL_DLL_00CD_ICEBALL_H_ */
