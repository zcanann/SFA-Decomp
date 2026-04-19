#include "dolphin/types.h"

extern u32 lbl_803DD648;
extern char* lbl_803DD64C;
extern u32 lbl_8033B1A0[];
extern char lbl_802C7B80[];

void MWTRACE(level, format)
int level;
char* format;
{
    u32* entry;
    char* current;

    entry = (u32*)((u8*)lbl_8033B1A0 + (lbl_803DD648++ * 0x14));
    if (level == 0xFF) {
        current = 0;
    } else {
        current = &lbl_802C7B80[level << 5];
    }
    lbl_803DD64C = current;
    entry[0] = 8;
    entry[1] = level;
}
