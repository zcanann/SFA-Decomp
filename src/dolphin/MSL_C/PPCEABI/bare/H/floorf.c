#include "dolphin.h"

float fn_80294724(float x) {
    int n = (int)x;
    float diff = (float)n - x;
    u32 bits;

    if (*(s32*)&diff != 0) {
        bits = *(u32*)&x;
        if ((s32)(bits & 0x7F800000) < 0x4B800000) {
            if ((s32)bits < 0) {
                return (float)(n - 1);
            }

            return (float)n;
        }
    }

    return x;
}
