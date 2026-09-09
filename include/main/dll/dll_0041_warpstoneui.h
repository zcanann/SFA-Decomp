#ifndef MAIN_DLL_DLL_0041_WARPSTONEUI_H_
#define MAIN_DLL_DLL_0041_WARPSTONEUI_H_

#include "global.h"

typedef struct
{
    s16 bit;
    u8 mapAct;
    u8 b3; /* unused/padding */
} WarpstoneEntry;

STATIC_ASSERT(sizeof(WarpstoneEntry) == 4);
STATIC_ASSERT(offsetof(WarpstoneEntry, bit) == 0);
STATIC_ASSERT(offsetof(WarpstoneEntry, mapAct) == 2);



void WarpstoneUI_setState(int val);
void WarpstoneUI_showUI(int arg);
void WarpstoneUI_frameEnd(void);
int WarpstoneUI_frameStart(void);
void WarpstoneUI_release(void);
void WarpstoneUI_initialise(void);

#endif
