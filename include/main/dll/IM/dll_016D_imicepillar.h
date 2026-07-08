#ifndef MAIN_DLL_IM_DLL_016D_IMICEPILLAR_H_
#define MAIN_DLL_IM_DLL_016D_IMICEPILLAR_H_

#include "types.h"

int imicepillar_getExtraSize(void);
int imicepillar_getObjectTypeId(void);
void imicepillar_free(void);
void imicepillar_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void imicepillar_hitDetect(void);
void imicepillar_update(void);
void imicepillar_init(void);
void imicepillar_release(void);
void imicepillar_initialise(void);

#endif /* MAIN_DLL_IM_DLL_016D_IMICEPILLAR_H_ */
