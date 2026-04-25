#include <dolphin.h>
#include <dolphin/os.h>

#include "dolphin/os/__os.h"

extern OSResetCallback lbl_803DDE68;
extern BOOL lbl_803DDE6C;
extern BOOL lbl_803DDE70;
extern OSTime lbl_803DDE78;
extern OSTime lbl_803DDE80;

void __OSResetSWInterruptHandler(s16 exception, OSContext* context) {
    OSResetCallback callback;

    lbl_803DDE80 = __OSGetSystemTime();
    while (__OSGetSystemTime() - lbl_803DDE80 < OSMicrosecondsToTicks(100) &&
           !(__PIRegs[0] & 0x00010000)) {
        ;
    }
    if (!(__PIRegs[0] & 0x00010000)) {
        lbl_803DDE70 = lbl_803DDE6C = TRUE;
        __OSMaskInterrupts(OS_INTERRUPTMASK_PI_RSW);
        if (lbl_803DDE68) {
            callback = lbl_803DDE68;
            lbl_803DDE68 = NULL;
            callback();
        }
    }
    __PIRegs[0] = 2;
}

BOOL OSGetResetButtonState(void) {
    BOOL enabled = OSDisableInterrupts();
    int state;
    u32 reg;
    OSTime now;

    now = __OSGetSystemTime();

    reg = __PIRegs[0];
    if (!(reg & 0x00010000)) {
        if (!lbl_803DDE6C) {
            lbl_803DDE6C = TRUE;
            state = lbl_803DDE78 ? TRUE : FALSE;
            lbl_803DDE80 = now;
        } else {
            state = lbl_803DDE78 || (OSMicrosecondsToTicks(100) < now - lbl_803DDE80)
                        ? TRUE
                        : FALSE;
        }
    } else if (lbl_803DDE6C) {
        lbl_803DDE6C = FALSE;
        state = lbl_803DDE70;
        if (state) {
            lbl_803DDE78 = now;
        } else {
            lbl_803DDE78 = 0;
        }
    } else if (lbl_803DDE78 && (now - lbl_803DDE78 < OSMillisecondsToTicks(40))) {
        state = TRUE;
    } else {
        state = FALSE;
        lbl_803DDE78 = 0;
    }

    lbl_803DDE70 = state;

    if (__gUnknown800030E3 & 0x3F) {
        OSTime fire = (__gUnknown800030E3 & 0x3F) * 60;
        fire = __OSStartTime + OSSecondsToTicks(fire);
        if (fire < now) {
            now -= fire;
            now = OSTicksToSeconds(now) / 2;
            if ((now & 1) == 0) {
                state = TRUE;
            } else {
                state = FALSE;
            }
        }
    }

    OSRestoreInterrupts(enabled);
    return state;
}
