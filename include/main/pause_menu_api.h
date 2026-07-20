#ifndef MAIN_PAUSE_MENU_API_H_
#define MAIN_PAUSE_MENU_API_H_

#include "types.h"

extern u8 pauseMenuState;

u8 pauseMenuGetState(void);
void pauseMenuFn_8012b77c(void);
void pauseMenuRunSubmenu(int submenu);
void pauseMenuDrawText(int unused1, int unused2, int unused3);
void gameTextFadeOut(void);
void pauseMenuSetupTitle(s32 fadeTarget, u8 index, u8 flags, u8 arg3);

#endif /* MAIN_PAUSE_MENU_API_H_ */
