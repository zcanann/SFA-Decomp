#include "ghidra_import.h"

/*
 * ReverbSTDCreate — initialize a standard reverb with delay lines
 * (~1012 instructions, range-checks 5 floats then sets up 12 delay
 * lines). Stubbed.
 */
#pragma dont_inline on
int ReverbSTDCreate(int reverb, float coloration, float time, float damping, float mix, float predelay)
{
    (void)reverb; (void)coloration; (void)time; (void)damping; (void)mix; (void)predelay;
    return 0;
}
#pragma dont_inline reset
