#ifndef MAIN_DLL_DLL_003B_MENU_H_
#define MAIN_DLL_DLL_003B_MENU_H_

#include "types.h"

extern u32 lbl_8031BF90[6];

s32 Menu_func0B(void);
void Menu_func0A(int v);
void Menu_func09_nop(void);
int Menu_func08(int* sel);
void Menu_func07(int v);
void Menu_func06(int resultId, int unused2, int unused3, int itemWidth, int defaultIndex);
void Menu_func05(int resultId, int unused2, int itemWidth, int defaultIndex);
void Menu_func04(int unused, int v);
void Menu_func03(int v);
void Menu_release(void);
void Menu_initialise(void);

#endif /* MAIN_DLL_DLL_003B_MENU_H_ */
