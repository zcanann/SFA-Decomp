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

/* Pattern wrappers. */
undefined4 FUN_80272eac(uint param_1, byte param_2, uint param_3) { return 0; }
undefined4 FUN_80272eb4(uint param_1) { return 0; }
undefined4 FUN_80272ebc(undefined2 param_1, byte param_2, uint param_3, byte param_4) { return 0; }
uint FUN_80272ec4(uint param_1) { return 0; }
void FUN_80272ecc(uint param_1, uint param_2, uint param_3) {}
void FUN_80272ed0(uint param_1, uint param_2, char param_3, char param_4) {}
void FUN_80272ed4(int param_1) {}
void FUN_80272ed8(uint param_1, int param_2, undefined4 param_3, char param_4, uint param_5,
                  int param_6, undefined4 param_7, char param_8, uint param_9) {}
void FUN_80272edc(uint param_1, undefined param_2, undefined4 param_3) {}
void FUN_80272ee0(uint param_1) {}
void FUN_80272ee4(uint param_1, byte *param_2) {}
void FUN_80272ee8(uint param_1, int param_2) {}
#pragma peephole reset
#pragma scheduling reset
