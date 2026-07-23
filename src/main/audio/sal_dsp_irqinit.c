#include "main/audio/sal_dsp.h"
#include "dolphin/os.h"

void hwInitIrq(void)
{
    oldState = OSDisableInterrupts();
    hwIrqLevel = 1;
}
