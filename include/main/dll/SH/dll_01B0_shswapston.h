#ifndef MAIN_DLL_SH_DLL_01B0_SHSWAPSTON_H_
#define MAIN_DLL_SH_DLL_01B0_SHSWAPSTON_H_

#include "main/game_object.h"

void warpstone_free(GameObject* obj, int mode);
void warpstone_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void warpstone_hitDetect(GameObject* obj);

#endif /* MAIN_DLL_SH_DLL_01B0_SHSWAPSTON_H_ */
