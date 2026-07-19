#ifndef MAIN_DLL_DLL_003B_MENU_H_
#define MAIN_DLL_DLL_003B_MENU_H_

#include "types.h"

s32 Menu_getItemCount(void);
void Menu_setArmed(int v);
void Menu_func09_nop(void);
int Menu_poll(int* sel);
void Menu_setCancelId(int v);
void Menu_addItemEx(int resultId, int unused2, int unused3, int itemWidth, int defaultIndex);
void Menu_addItem(int resultId, int unused2, int itemWidth, int defaultIndex);
void Menu_open(int unused, int v);
void Menu_reset(int v);
void Menu_release(void);
void Menu_initialise(void);

#endif /* MAIN_DLL_DLL_003B_MENU_H_ */
