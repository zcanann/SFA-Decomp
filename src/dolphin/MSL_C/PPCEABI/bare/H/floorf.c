#include "dolphin/types.h"

float floorf(float value) {
    int truncated = value;
    float difference = (float)truncated - value;
    u32 valueBits;

    if (*(s32*)&difference != 0) {
        valueBits = *(u32*)&value;
        if ((s32)(valueBits & 0x7F800000) < 0x4B800000) {
            goto small_magnitude;
        }

        return value;
small_magnitude:
        if (valueBits & 0x80000000) {
            --truncated;
            return (float)truncated;
        }

        return (float)truncated;
    }

    return value;
}
