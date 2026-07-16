#ifndef MAIN_DLL_DLL_003D_TITLEMENUITEM_H_
#define MAIN_DLL_DLL_003D_TITLEMENUITEM_H_

#include "main/dll/titlemenuitem_struct.h"

void fn_80131F0C(void);
int TitleMenuItem_isChanged(TitleMenuItem* item);
void TitleMenuItem_setVal(TitleMenuItem* item, int value);
s16 TitleMenuItem_getVal(TitleMenuItem* item);
void TitleMenuItem_setEnabled(TitleMenuItem* item, int enabled);
int TitleMenuItem_isEnabled(TitleMenuItem* item);
void TitleMenuItem_render(TitleMenuItem* item, int unused, int alpha);
void TitleMenuItem_update(TitleMenuItem* item);
void TitleMenuItem_setAButtonToggle(TitleMenuItem* item, int enabled);
void TitleMenuItem_free(void);
void TitleMenuItem_initialise(void);
TitleMenuItem* TitleMenuItem_createWithWindow(int phraseId, int windowId, s16 minValue, s16 maxValue, s16 value);
TitleMenuItem* TitleMenuItem_create(s16 x, s16 y, s16 minValue, s16 maxValue, s16 value);
TitleMenuItem* TitleMenuItem_createWithText(s16 x, s16 y, s16 minValue, s16 maxValue, s16 value, int textId);
void TitleMenuItem_release(void);

#endif
