#ifndef MAIN_DLL_DLL_0038_WEIRDUNUSEDMENU_H_
#define MAIN_DLL_DLL_0038_WEIRDUNUSEDMENU_H_

#include "global.h"

typedef struct WeirdMenuWork
{
    u8 pad0[0x16 - 0x0];   /* 0x00-0x15: unknown, not touched here */
    u16 widgetFlagsA;      /* 0x16: OR'd with WIDGET_FLAG_SAVING */
    u8 pad18[0x52 - 0x18]; /* 0x18-0x51: unknown, not touched here */
    u16 widgetFlagsB;      /* 0x52: OR'd with WIDGET_FLAG_SAVING */
    u8 pad54[0x78 - 0x54]; /* 0x54-0x77: unknown, not touched here */
} WeirdMenuWork;

void WeirdUnusedMenu_render(void);
void WeirdUnusedMenu_frameEnd(void);
int WeirdUnusedMenu_run(void);
void WeirdUnusedMenu_release(void);
void WeirdUnusedMenu_initialise(void);

#endif /* MAIN_DLL_DLL_0038_WEIRDUNUSEDMENU_H_ */
