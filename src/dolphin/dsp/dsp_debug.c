#include <dolphin/dsp.h>

#include "dolphin/dsp/__dsp.h"

void __DSP_debug_printf(const char* fmt, ...) {}

DSPTaskInfo* __DSPGetCurrentTask(void) {
    return __DSP_curr_task;
}
