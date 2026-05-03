#include "dolphin.h"

extern u32 lbl_803DE410;

u32 rand(void) {
    lbl_803DE410 = lbl_803DE410 * 0x19660D + 0x3C6EF35F;
    return lbl_803DE410;
}

void srand(u32 seed) {
    lbl_803DE410 = seed;
}
