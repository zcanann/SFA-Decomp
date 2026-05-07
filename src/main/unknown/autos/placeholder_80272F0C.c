#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80272F0C.h"

extern u8 lbl_803BD150[];
extern u8 lbl_803BE378[];
extern u8 lbl_803DE280;
extern u8 lbl_803DE281;
extern u32 lbl_803DE284;

/*
 * --INFO--
 *
 * Function: fn_80272EA4
 * EN v1.0 Address: 0x80272EA4
 * EN v1.0 Size: 200b
 */
#pragma scheduling off
#pragma peephole off
void fn_80272EA4(void)
{
    int count;
    int progress;
    u8 *outerEntry;
    u8 *tailEntry;
    int outerLoops;
    int tailRemaining;

    lbl_803DE280 = 0;
    lbl_803DE281 = 3;
    count = lbl_803BD150[0x210];
    progress = 0;
    if (count != 0) {
        if (8 < count) {
            outerLoops = (count - 1) >> 3;
            outerEntry = lbl_803BE378;
            if ((int)(count - 8) > 0) {
                do {
                    outerEntry[0x008] = 0;
                    progress += 8;
                    outerEntry[0x06c] = 0;
                    outerEntry[0x0d0] = 0;
                    outerEntry[0x134] = 0;
                    outerEntry[0x198] = 0;
                    outerEntry[0x1fc] = 0;
                    outerEntry[0x260] = 0;
                    outerEntry[0x2c4] = 0;
                    outerEntry += 0x320;
                    outerLoops--;
                } while (outerLoops != 0);
            }
        }
        tailEntry = lbl_803BE378 + progress * 0x64;
        tailRemaining = count - progress;
        if (progress < (int)count) {
            do {
                tailEntry[8] = 0;
                tailEntry += 0x64;
                tailRemaining--;
            } while (tailRemaining != 0);
        }
    }
    lbl_803DE284 = 0;
}

void fn_80272F6C(void) {}
#pragma peephole reset
#pragma scheduling reset
