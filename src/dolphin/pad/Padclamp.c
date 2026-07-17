#include <dolphin.h>
PADClampRegion ClampRegion = {
    30,
    180,
    15,
    72,
    40,
    15,
    59,
    31,
};


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
            ClampStick(&status->stickX, &status->stickY, ClampRegion.maxStick, ClampRegion.xyStick, ClampRegion.minStick);
            ClampStick(
                &status->substickX, &status->substickY, ClampRegion.maxSubstick, ClampRegion.xySubstick,
                ClampRegion.minSubstick
            );
            if (status->triggerLeft <= ClampRegion.minTrigger) {
                status->triggerLeft = 0;
            } else {
                if (ClampRegion.maxTrigger < status->triggerLeft) {
                    status->triggerLeft = ClampRegion.maxTrigger;
                }
                status->triggerLeft -= ClampRegion.minTrigger;
            }
            if (status->triggerRight <= ClampRegion.minTrigger) {
                status->triggerRight = 0;
            } else {
                if (ClampRegion.maxTrigger < status->triggerRight) {
                    status->triggerRight = ClampRegion.maxTrigger;
                }
                status->triggerRight -= ClampRegion.minTrigger;
            }
        }
    }
}

