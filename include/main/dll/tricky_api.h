#ifndef MAIN_DLL_TRICKY_API_H_
#define MAIN_DLL_TRICKY_API_H_

#include "global.h"

void setAButtonIcon(int icon);
void setBButtonIcon(int icon);
void cutSceneFn_8011dd30(void);
void drawViewFinderHud(void);
void hudSetMagicCostPreview(u8 value);
void fearTestMeterSetFadeIn(u32 value);
void hudFn_8011f38c(u8 value);
void showDeathMenu(void);
void resetYbutton(void);
int getYButtonItem(s16* out);
void gameUiResetMenuState(void);
void hudFn_8011f6f0(u8 value);

#endif /* MAIN_DLL_TRICKY_API_H_ */
