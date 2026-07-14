#ifndef MAIN_DLL_CMENU_H_
#define MAIN_DLL_CMENU_H_

#include "ghidra_import.h"

int cMenuSetItems(s16* items, char useTricky);
int cMenuRingModelRenderFn(int obj, int block, int idx);
void drawTrickyHudOverlay(int obj, int unused1, int unused2);
int cMenuRingIconRenderFn(int obj, int block, int idx);
void hudDrawCMenu(int p1, int p2, int p3);
void cMenuRotateFn_80124d80(void);

#endif /* MAIN_DLL_CMENU_H_ */
