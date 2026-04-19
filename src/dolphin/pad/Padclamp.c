#include <dolphin.h>
#include <dolphin/pad.h>
#include "dolphin/fake_tgmath.h"

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

extern PADClampExtents lbl_803DD1E8;

#define PAD_CLAMP_RAD_STICK    56
#define PAD_CLAMP_RAD_SUBSTICK 44

// prototypes
static void ClampStick(s8* px, s8* py, s8 max, s8 xy, s8 min);
static void ClampCircle(s8* px, s8* py, s8 radius, s8 min);
static void ClampTrigger(u8* trigger, u8 min, u8 max);

static void ClampStick(s8* px, s8* py, s8 max, s8 xy, s8 min) {
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

static void ClampCircle(s8* px, s8* py, s8 radius, s8 min) {
    int x = *px;
    int y = *py;
    int squared;
    int length;

    if (-min < x && x < min) {
        x = 0;
    } else if (0 < x) {
        x -= min;
    } else {
        x += min;
    }

    if (-min < y && y < min) {
        y = 0;
    } else if (0 < y) {
        y -= min;
    } else {
        y += min;
    }

    squared = x * x + y * y;
    if (radius * radius < squared) {
        length = sqrtf(squared);
        x = (x * radius) / length;
        y = (y * radius) / length;
    }

    *px = x;
    *py = y;
}

static void ClampTrigger(u8* trigger, u8 min, u8 max) {
    if (*trigger <= min) {
        *trigger = 0;
    } else {
        if (max < *trigger) {
            *trigger = max;
        }
        *trigger -= min;
    }
}

void PADClamp(PADStatus * status) {
    int i;

    for (i = 0; i < 4; i++, status++) {
        if (status->err == PAD_ERR_NONE) {
            ClampStick(&status->stickX, &status->stickY, lbl_803DD1E8.maxStick, lbl_803DD1E8.xyStick, lbl_803DD1E8.minStick);
            ClampStick(
                &status->substickX, &status->substickY, lbl_803DD1E8.maxSubstick, lbl_803DD1E8.xySubstick,
                lbl_803DD1E8.minSubstick
            );
            ClampTrigger(&status->triggerLeft, lbl_803DD1E8.minTrigger, lbl_803DD1E8.maxTrigger);
            ClampTrigger(&status->triggerRight, lbl_803DD1E8.minTrigger, lbl_803DD1E8.maxTrigger);
        }
    }
}

void PADClampCircle(PADStatus* status) {
    int i;
    for (i = 0; i < 4; ++i, status++) {
        if (status->err == PAD_ERR_NONE) {
            ClampCircle(&status->stickX, &status->stickY, PAD_CLAMP_RAD_STICK, lbl_803DD1E8.minStick);
            ClampCircle(&status->substickX, &status->substickY, PAD_CLAMP_RAD_SUBSTICK, lbl_803DD1E8.minSubstick);
            ClampTrigger(&status->triggerLeft, lbl_803DD1E8.minTrigger, lbl_803DD1E8.maxTrigger);
            ClampTrigger(&status->triggerRight, lbl_803DD1E8.minTrigger, lbl_803DD1E8.maxTrigger);
        }
    }
}
