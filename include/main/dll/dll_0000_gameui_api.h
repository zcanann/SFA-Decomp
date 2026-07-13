#ifndef MAIN_DLL_DLL_0000_GAMEUI_API_H_
#define MAIN_DLL_DLL_0000_GAMEUI_API_H_

#include "types.h"

typedef int (*CMenuGetSelectedItemIntFn)(void);

s16 cMenuGetSelectedItem(void);
void drawHudBox(s16 x, s16 y, s16 width, s16 height, int alpha, u8 flags);
u8 fn_8012DDA4(void);
int registerNewScore(s8 tableId, int score, u8 kind, int mode);
void timeListFn_8012df14(void);
void textureFreeFn_8012fcec(void);
void viewFn_80129c74(void);

#define cMenuGetSelectedItemInt() (((CMenuGetSelectedItemIntFn)cMenuGetSelectedItem)())

#endif /* MAIN_DLL_DLL_0000_GAMEUI_API_H_ */
