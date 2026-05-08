#include "global.h"
#include "main/dll/dll_4D.h"

typedef struct TitleMenuTextEntry {
    u8 pad0[0x16];
    u16 flags;
    s8 pad18[0x24];
} TitleMenuTextEntry;

typedef struct TitleMenuControl {
    void *vtable;
} TitleMenuControl;

typedef struct MenuPanelGroup {
    u8 pad00[0x30];
    TitleMenuTextEntry *entries;
    u32 unused34;
    u8 count;
    u8 pad39[7];
} MenuPanelGroup;

extern MenuPanelGroup lbl_8031ACB8;

extern u8 lbl_803DBA28;
extern u8 lbl_803DC968;
extern TitleMenuControl *lbl_803DCAA0;
extern TitleMenuControl *lbl_803DCAA4;
extern u8 lbl_803DD706;
extern u8 *lbl_803DD708;
extern int lbl_803A87D0[8];

extern int isCheatActive(int);
extern int isCheatUnlocked(int);

/*
 * --INFO--
 *
 * Function: fn_8011C5CC
 * EN v1.0 Address: 0x8011C5CC
 * EN v1.0 Size: 488b
 */
#pragma scheduling off
#pragma peephole off
void fn_8011C5CC(void) {
    MenuPanelGroup *p;

    if ((s8)lbl_803DBA28 != -1) {
        ((void (**)(void))lbl_803DCAA0->vtable)[2]();
    }
    lbl_803DBA28 = 3;

    p = &lbl_8031ACB8;
    lbl_803A87D0[0] = ((int (**)(int, int, int, int, s16))lbl_803DCAA4->vtable)[3](
        0x36b, 0x22, 0, 1, (s16)(lbl_803DD708[2] == 0));

    if (isCheatUnlocked(3) != 0 && lbl_803DC968 == 0) {
        p->entries[p->count - 2].pad18[3] = p->count - 1;
        p->entries[p->count - 1].flags &= ~0x4000;

        lbl_803A87D0[1] = ((int (**)(int, int, int, int, s16))lbl_803DCAA4->vtable)[3](
            0x36b, 0x23, 0, 1, (s16)(isCheatActive(3) == 0));
    } else {
        p->entries[p->count - 2].pad18[3] = -1;
        p->entries[p->count - 1].flags |= 0x4000;
    }

    ((void (**)(int, int))lbl_803DCAA0->vtable)[8](lbl_803A87D0[0], 1);

    ((void (**)(TitleMenuTextEntry *, int, int, int, int, int, int, int, int, int, int, int))
        lbl_803DCAA0->vtable)[1](
        p->entries, p->count, 0, 0, 0, 0, 0x14, 0xc8,
        0xff, 0xff, 0xff, 0xff);

    lbl_803DD706 = 2;
}
#pragma peephole reset
#pragma scheduling reset
