#ifndef MAIN_DLL_DLL_0041_WARPSTONEUI_H_
#define MAIN_DLL_DLL_0041_WARPSTONEUI_H_

#include "types.h"

typedef struct
{
    s16 bit;
    u8 mapAct;
    u8 b3; /* unused/padding */
} WarpstoneEntry;

typedef struct
{
    u16 textId;
    u16 boxId;
    s16 x;
    s16 y;
    u8 pad08[0x12];
    s8 previousItem;
    s8 nextItem;
    u8 pad1C[0x20];
} WarpstoneMenuItem;

int WarpstoneUI_getMenuItems(const WarpstoneMenuItem* templates, WarpstoneMenuItem* items,
                             const WarpstoneEntry* entries, int count, int* selectedIndices);
void WarpstoneUI_setState(int val);
void WarpstoneUI_showUI(int arg);
void WarpstoneUI_frameEnd(void);
int WarpstoneUI_frameStart(void);
void WarpstoneUI_release(void);
void WarpstoneUI_initialise(void);

#endif
