#include "dolphin.h"

// rand.c from Runtime library

extern u32 lbl_803DF090;

asm u32 rand(void) {
    nofralloc
    lwz r0, lbl_803DF090
    lis r3, 25
    addi r3, r3, 0x660D
    mullw r3, r0, r3
    addis r3, r3, 0x3C6F
    addi r0, r3, -3233
    stw r0, lbl_803DF090
    lwz r3, lbl_803DF090
    blr
}

void srand(u32 seed) {
    lbl_803DF090 = seed;
}
