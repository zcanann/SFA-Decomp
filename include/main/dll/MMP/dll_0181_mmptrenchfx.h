#ifndef MAIN_DLL_MMP_DLL_0181_MMPTRENCHFX_H_
#define MAIN_DLL_MMP_DLL_0181_MMPTRENCHFX_H_

#include "main/game_object.h"
#include "types.h"

int mmp_trenchfx_getExtraSize(void);
int mmp_trenchfx_getObjectTypeId(void);
void mmp_trenchfx_free(int obj);
void mmp_trenchfx_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void mmp_trenchfx_hitDetect(void);
void mmp_trenchfx_update(GameObject* obj);
void mmp_trenchfx_init(GameObject* obj, int data);
void mmp_trenchfx_release(void);
void mmp_trenchfx_initialise(void);

#endif /* MAIN_DLL_MMP_DLL_0181_MMPTRENCHFX_H_ */
