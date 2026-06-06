#include <dolphin.h>

void OSStartStopwatch(OSStopwatch* sw) {
    sw->running = TRUE;
    sw->last = OSGetTime();
}

void OSStopStopwatch(OSStopwatch* sw) {
    OSTime interval;

    if (sw->running) {
        interval = OSGetTime() - sw->last;
        sw->total += interval;
        sw->running = FALSE;
        sw->hits++;
        if (sw->max < interval) {
            sw->max = interval;
        }
        if (interval < sw->min) {
            sw->min = interval;
        }
    }
}

OSTime OSCheckStopwatch(OSStopwatch* sw) {
    OSTime currTotal;

    currTotal = sw->total;
    if (sw->running) {
        currTotal += OSGetTime() - sw->last;
    }
    return currTotal;
}
