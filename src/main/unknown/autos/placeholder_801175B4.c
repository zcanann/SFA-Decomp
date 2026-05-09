#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_801175B4.h"
#include "dolphin/os.h"

extern void *threadMainAlt_80117460(void *);
extern void *thpAudioThreadMain(void *);
extern u8 lbl_803A4448[];
extern int lbl_803DD658;

/*
 * --INFO--
 *
 * Function: fn_801175A4
 * EN v1.0 Address: 0x801175A4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801175B4
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int fn_801175A4(OSPriority priority, void *param)
{
    u8 *base = lbl_803A4448;

    if (param != NULL) {
        if (OSCreateThread((OSThread *)(base + 0x1058), threadMainAlt_80117460, param,
                           base + 0x1058, 0x1000, priority, 1) == 0) {
            return 0;
        }
    } else {
        if (OSCreateThread((OSThread *)(base + 0x1058), thpAudioThreadMain, NULL,
                           base + 0x1058, 0x1000, priority, 1) == 0) {
            return 0;
        }
    }
    OSInitMessageQueue((OSMessageQueue *)(base + 0x38), (OSMessage *)(base + 0xc), 3);
    OSInitMessageQueue((OSMessageQueue *)(base + 0x18), (OSMessage *)base, 3);
    lbl_803DD658 = 1;
    return 1;
}
#pragma peephole reset
#pragma scheduling reset
