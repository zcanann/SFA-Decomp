#include "dolphin/types.h"

float floorf(float x) {
    int n = (int)x;
    float diff = (float)n - x;
    u32 bits;

    if (*(s32*)&diff != 0) {
        bits = *(u32*)&x;
        if ((s32)(bits & 0x7F800000) < 0x4B800000) {
            goto small;
        }

        return x;
small:
        if (bits & 0x80000000) {
            --n;
            return (float)n;
        }

        return (float)n;
    }

    return x;
}
