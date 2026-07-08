#include "main/audio/adsr_lowprec.h"

#pragma exceptions on

extern u32 adsrHandle(int p1, int p2, int p3);

int adsrHandleLowPrecision(int p1, int p2, int p3)
{
    u8 i;

    for (i = 0; i < 15; i++)
    {
        if (adsrHandle(p1, p2, p3) != 0)
        {
            return 1;
        }
    }
    return 0;
}
