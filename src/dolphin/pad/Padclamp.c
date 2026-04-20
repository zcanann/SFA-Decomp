#include <dolphin.h>
#include <dolphin/pad.h>
#include <dolphin/si.h>

#include "dolphin/si/__si.h"

extern u32 XPatchBits;
extern u32 AnalogMode;
extern PADStatus Origin[4];

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
void ClampCircle_8024E354(s32 chan);

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

void PADClamp(PADStatus * status) {
    int i;

    for (i = 0; i < 4; i++, status++) {
        if (status->err == PAD_ERR_NONE) {
            ClampStick(&status->stickX, &status->stickY, lbl_803DD1E8.maxStick, lbl_803DD1E8.xyStick, lbl_803DD1E8.minStick);
            ClampStick(
                &status->substickX, &status->substickY, lbl_803DD1E8.maxSubstick, lbl_803DD1E8.xySubstick,
                lbl_803DD1E8.minSubstick
            );
            if (status->triggerLeft <= lbl_803DD1E8.minTrigger) {
                status->triggerLeft = 0;
            } else {
                if (lbl_803DD1E8.maxTrigger < status->triggerLeft) {
                    status->triggerLeft = lbl_803DD1E8.maxTrigger;
                }
                status->triggerLeft -= lbl_803DD1E8.minTrigger;
            }
            if (status->triggerRight <= lbl_803DD1E8.minTrigger) {
                status->triggerRight = 0;
            } else {
                if (lbl_803DD1E8.maxTrigger < status->triggerRight) {
                    status->triggerRight = lbl_803DD1E8.maxTrigger;
                }
                status->triggerRight -= lbl_803DD1E8.minTrigger;
            }
        }
    }
}

void ClampCircle_8024E354(s32 chan) {
    PADStatus* origin;
    u32 chanBit = PAD_CHAN0_BIT >> chan;

    origin = &Origin[chan];
    switch (AnalogMode & 0x00000700u) {
    case 0x00000000u:
    case 0x00000500u:
    case 0x00000600u:
    case 0x00000700u:
        origin->triggerLeft &= ~15;
        origin->triggerRight &= ~15;
        origin->analogA &= ~15;
        origin->analogB &= ~15;
        break;
    case 0x00000100u:
        origin->substickX &= ~15;
        origin->substickY &= ~15;
        origin->analogA &= ~15;
        origin->analogB &= ~15;
        break;
    case 0x00000200u:
        origin->substickX &= ~15;
        origin->substickY &= ~15;
        origin->triggerLeft &= ~15;
        origin->triggerRight &= ~15;
        break;
    case 0x00000300u: break;
    case 0x00000400u: break;
    }

    origin->stickX -= 128;
    origin->stickY -= 128;
    origin->substickX -= 128;
    origin->substickY -= 128;

    if (XPatchBits & chanBit) {
        if (64 < origin->stickX && (SIGetType(chan) & 0xFFFF0000) == SI_GC_CONTROLLER) {
            origin->stickX = 0;
        }
    }
}
