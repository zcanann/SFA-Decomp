#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_801175B4.h"
#include "dolphin/os.h"

extern void *AudioDecoderForOnMemory(void *);
extern void *AudioDecoder(void *);
extern u8 lbl_803A4448[];
extern int lbl_803DD658;

/*
 * --INFO--
 *
 * Function: CreateAudioDecodeThread
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
int CreateAudioDecodeThread(OSPriority priority, void *param)
{
    register u8 *base;

    asm {
        lis r3, lbl_803A4448@ha
        addi base, r3, lbl_803A4448@l
    }

    if (param != NULL) {
        if (OSCreateThread((OSThread *)(base + 0x1058), AudioDecoderForOnMemory, param,
                           base + 0x1058, 0x1000, priority, 1) == 0) {
            return 0;
        }
    } else {
        if (OSCreateThread((OSThread *)(base + 0x1058), AudioDecoder, NULL,
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
