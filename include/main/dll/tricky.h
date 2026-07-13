#ifndef MAIN_DLL_TRICKY_H_
#define MAIN_DLL_TRICKY_H_

#include "main/dll/tricky_api.h"

void gameUiLoadResources(void);
void pauseMenuTextDrawFn(int x0, int y0, int x1, int y1, f32 u0, f32 v0, f32 u1, f32 v1);
void hudDrawAirMeter(void);
void fearTestMeterDraw(void);
void pauseMenuMapFn_8011de20(void* this, u8 a, s16 b, int c);
void fn_8011EF50(f32 f1, f32 f2, f32 f3, f32 f4, u16 a, u16 b, u16 c);
void arwingHudSetVisible(u32 mode);

#endif /* MAIN_DLL_TRICKY_H_ */
