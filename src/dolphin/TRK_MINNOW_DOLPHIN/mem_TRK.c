/* TODO: restore stripped imported address metadata if needed. */

/**
 * mem_TRK.c
 * Description:
 */

#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/mem_TRK.h"

#pragma dont_inline on
void TRK_fill_mem(void* dst, int val, u32 n) {
    u32 v;
    u32 i;
    union {
        u8* p8;
        u32* p32;
    } p;

    v = (u8)val;
    p.p8 = (u8*)dst - 1;

    if (n >= 32) {
        i = (~(u32)p.p8) & 3;

        if (i) {
            n -= i;

            do {
                *++p.p8 = (u8)v;
            } while (--i);
        }

        if (v)
            v |= v << 24 | v << 16 | v << 8;

        p.p32 = (u32*)(p.p8 - 3);
        i = n >> 5;
        if (i != 0) {
            do {
                p.p32[1] = v;
                p.p32[2] = v;
                p.p32[3] = v;
                p.p32[4] = v;
                p.p32[5] = v;
                p.p32[6] = v;
                p.p32[7] = v;
                p.p32 += 8;
                *p.p32 = v;
            } while (--i);
        }

        i = (n >> 2) & 7;

        if (i != 0) {
            do {
                *++p.p32 = v;
            } while (--i);
        }

        p.p8 = (u8*)p.p32 + 3;
        {
            u32 mask = 3;
            n &= mask;
        }
    }

    if (n)
        do {
            *++p.p8 = (u8)v;
        } while (--n);
}
#pragma dont_inline reset

__declspec(section ".init") void* TRK_memcpy(void* dst, const void* src, unsigned int n) {
    const unsigned char* s = (const unsigned char*)src - 1;
    unsigned char* d = (unsigned char*)dst - 1;

    n++;
    while (--n != 0)
        *++d = *++s;
    return dst;
}

__declspec(section ".init") void* TRK_memset(void* dst, int val, unsigned int n) {
    TRK_fill_mem(dst, val, n);

    return dst;
}
