#include "dolphin.h"

// rand.c from Runtime library

extern u32 lbl_803DF090;

u32 rand(void)
{
	lbl_803DF090 = lbl_803DF090 * 0x19660D + 0x3C6EF35F;
	return lbl_803DF090;
}

void srand(u32 seed) { lbl_803DF090 = seed; }
