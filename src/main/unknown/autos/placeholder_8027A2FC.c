#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_8027A2FC.h"

extern u8 lbl_803CAAD0[];
extern u8 lbl_803CAB50[];

/*
 * --INFO--
 *
 * Function: voiceUnregister
 * EN v1.0 Address: 0x8027A2B4
 * EN v1.0 Size: 124b
 * EN v1.1 Address: 0x8027A2FC
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void voiceUnregister(int obj)
{
    u32 a;
    u8 b;
    u8 c;
    u8 key;
    u8 *slot;

    a = *(u32 *)(obj + 0xf4);
    if (a == 0xffffffff) return;
    b = *(u8 *)(obj + 0x121);
    if (b == 0xff) return;
    c = *(u8 *)(obj + 0x122);
    key = (u8)a;
    if (c == 0xff) {
        u8 *base = lbl_803CAB50;
        slot = base + key;
        if (*slot != key) return;
        *slot = 0xff;
    } else {
        u8 *base = lbl_803CAAD0;
        slot = base + c * 16 + b;
        if (*slot != key) return;
        *slot = 0xff;
    }
}
