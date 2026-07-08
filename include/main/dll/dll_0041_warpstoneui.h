#ifndef MAIN_DLL_DLL_0041_WARPSTONEUI_H_
#define MAIN_DLL_DLL_0041_WARPSTONEUI_H_

#include "types.h"

typedef struct
{
    s16 bit;
    u8 mapAct;
    u8 b3; /* unused/padding */
} WarpstoneEntry;

int WarpstoneUI_getMenuItems(u8* src, u8* dst, u8* ids, int count, int* out);
void WarpstoneUI_setState(int val);
void WarpstoneUI_showUI(int arg);
void WarpstoneUI_frameEnd(void);
int WarpstoneUI_frameStart(void);
void WarpstoneUI_release(void);
void WarpstoneUI_initialise(void);

#endif
