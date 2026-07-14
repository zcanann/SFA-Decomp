#ifndef MAIN_PAUSE_MENU_API_H_
#define MAIN_PAUSE_MENU_API_H_

#include "types.h"

extern u8 pauseMenuState;

u8 pauseMenuGetState(void);
void pauseMenuFn_8012b77c(void);
void pauseMenuRunSubmenu(int submenu);
void pauseMenuDrawText(int unused1, int unused2, int unused3);
#ifdef PAUSE_MENU_DIRECT_INT_SETUP_TITLE_CALL
void pauseMenuSetupTitle(int fadeTarget, int index, int flags, int arg3);
#else
void pauseMenuSetupTitle(s32 fadeTarget, u8 index, u8 flags, u8 arg3);
#endif

#endif /* MAIN_PAUSE_MENU_API_H_ */
