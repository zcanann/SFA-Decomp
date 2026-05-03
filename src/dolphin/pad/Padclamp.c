#include <dolphin.h>
#include <dolphin/pad.h>
typedef struct PADClampExtents {
    u8 minTrigger;
    u8 maxTrigger;
    s8 minStick;
    s8 maxStick;
    s8 xyStick;
    s8 minSubstick;
    s8 maxSubstick;
    s8 xySubstick;
} PADClampExtents;

extern PADClampExtents lbl_803DC580;

#define PAD_CLAMP_RAD_STICK    56
#define PAD_CLAMP_RAD_SUBSTICK 44

// prototypes
void ClampStick(s8* px, s8* py, s8 max, s8 xy, s8 min);

void ClampStick(s8* px, s8* py, s8 max, s8 xy, s8 min) {
    int x = *px;
    int y = *py;
    int signX;
    int signY;
    int d;

    if (0 <= x) {
        signX = 1;
    } else {
        signX = -1;
        x = -x;
    }

    if (0 <= y) {
        signY = 1;
    } else {
        signY = -1;
        y = -y;
    }

    if (x <= min) {
        x = 0;
    } else {
        x -= min;
    }
    if (y <= min) {
        y = 0;
    } else {
        y -= min;
    }

    if (x == 0 && y == 0) {
        *px = *py = 0;
        return;
    }

    if (xy * y <= xy * x) {
        d = xy * x + (max - xy) * y;
        if (xy * max < d) {
            x = (s8)(xy * max * x / d);
            y = (s8)(xy * max * y / d);
        }
    } else {
        d = xy * y + (max - xy) * x;
        if (xy * max < d) {
            x = (s8)(xy * max * x / d);
            y = (s8)(xy * max * y / d);
        }
    }

    *px = (s8)(signX * x);
    *py = (s8)(signY * y);
}

void PADClamp(PADStatus * status) {
    int i;

    for (i = 0; i < 4; i++, status++) {
        if (status->err == PAD_ERR_NONE) {
            ClampStick(&status->stickX, &status->stickY, lbl_803DC580.maxStick, lbl_803DC580.xyStick, lbl_803DC580.minStick);
            ClampStick(
                &status->substickX, &status->substickY, lbl_803DC580.maxSubstick, lbl_803DC580.xySubstick,
                lbl_803DC580.minSubstick
            );
            if (status->triggerLeft <= lbl_803DC580.minTrigger) {
                status->triggerLeft = 0;
            } else {
                if (lbl_803DC580.maxTrigger < status->triggerLeft) {
                    status->triggerLeft = lbl_803DC580.maxTrigger;
                }
                status->triggerLeft -= lbl_803DC580.minTrigger;
            }
            if (status->triggerRight <= lbl_803DC580.minTrigger) {
                status->triggerRight = 0;
            } else {
                if (lbl_803DC580.maxTrigger < status->triggerRight) {
                    status->triggerRight = lbl_803DC580.maxTrigger;
                }
                status->triggerRight -= lbl_803DC580.minTrigger;
            }
        }
    }
}

