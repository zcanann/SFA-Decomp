#ifndef MAIN_DLL_TRICKY_API_H_
#define MAIN_DLL_TRICKY_API_H_

#include "global.h"

void setAButtonIcon(int icon);
void setBButtonIcon(int icon);
void cutSceneFn_8011dd30(void);
void drawViewFinderHud(void);
void fn_8011F34C(u8 value);
void fn_8011F6D4(u32 value);
void hudFn_8011f38c(u8 value);
void showDeathMenu(void);
void resetYbutton(void);
u16 getYButtonItem(s16* out);
void gameUiResetMenuState(void);

#define getYButtonItemLegacy(out) ((int (*)(s16*))getYButtonItem)(out)

#endif /* MAIN_DLL_TRICKY_API_H_ */
