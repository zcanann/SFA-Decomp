#ifndef MAIN_DLL_DLL_02C0_FRONT_API_H_
#define MAIN_DLL_DLL_02C0_FRONT_API_H_

#include "types.h"

void titleScreenPositionElements(f32 x, f32 y);
void titleScreenShowCopyright(u8 enabled);
void titleScreenFn_801368d4(void);
void titleScreenTextDrawFunc(int x0, int y0, int x1, int y1,
                             f32 u0, f32 v0, f32 u1, f32 v1);
void creditsStart_(void);
int gameTextFn_80134be8(void);
u8 shouldShowCredits(void);

#endif /* MAIN_DLL_DLL_02C0_FRONT_API_H_ */
