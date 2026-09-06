#include "global.h"
#include "main/fileio.h"
#include "main/frame_timing.h"
#include "main/gameloop_api.h"
#include "main/pad.h"
#include "dolphin/pad.h"
#include "string.h"

u8 gPadMenuStickRepeatDelay = 5;

/* Synthesized C-stick-as-direction bits OR'd into the extended button word. */
#define PAD_BUTTON_CSTICK_UP    0x10000
#define PAD_BUTTON_CSTICK_DOWN  0x20000
#define PAD_BUTTON_CSTICK_LEFT  0x40000
#define PAD_BUTTON_CSTICK_RIGHT 0x80000

/* Synthesized digital-trigger bits (analog trigger past threshold). */
#define PAD_ANALOG_TRIGGER_R 0x20
#define PAD_ANALOG_TRIGGER_L 0x40

typedef struct PadStateBlock {
    u32 previousButtons[4];        /* 0x00 */
    u32 currentButtons[4];         /* 0x10 */
    u32 releasedButtons[4];        /* 0x20 */
    u32 pressedButtons[4];         /* 0x30 */
    PADStatus statusBuffers[2][4]; /* 0x40, two 0x30-byte PADRead buffers */
} PadStateBlock;

STATIC_ASSERT(offsetof(PadStateBlock, currentButtons) == 0x10);
STATIC_ASSERT(offsetof(PadStateBlock, releasedButtons) == 0x20);
STATIC_ASSERT(offsetof(PadStateBlock, pressedButtons) == 0x30);
STATIC_ASSERT(offsetof(PadStateBlock, statusBuffers[0]) == 0x40);
STATIC_ASSERT(offsetof(PadStateBlock, statusBuffers[1]) == 0x70);
STATIC_ASSERT(sizeof(PadStateBlock) == 0xA0);

extern PADStatus gPadStatuses[2][4];

u8 gPadStatusBufferIndex;
s8 gPadLastStickX[4];
s8 gPadLastStickY[4];
s8 gPadMenuStickXHoldTimer[4];
s8 gPadMenuStickYHoldTimer[4];
s8 gPadMenuStickXSign[4];
s8 gPadMenuStickYSign[4];
u16 gPadTriggersPressed[4];
u16 gPadTriggersReleased[4];
u16 gPadTriggers[4];
u16 gPadPrevTriggers[4];
u32 gPadResetMask;
f32 gRumbleTimer;
u8 rumbleEnabled;
u8 joypadDisabled;

void stopRumble2(void) {
    if (rumbleEnabled != 0) {
        PADControlMotor(0, PAD_MOTOR_STOP_HARD);
        gRumbleTimer = 0.0f;
    }
}

void stopRumble(void) {
    if (rumbleEnabled != 0) {
        PADControlMotor(0, PAD_MOTOR_STOP);
        gRumbleTimer = 0.0f;
    }
}

void doRumble(f32 duration) {
    if (rumbleEnabled != 0 && getGameState() == 1) {
        f32 rumbleTimer;

        PADControlMotor(0, PAD_MOTOR_RUMBLE);
        rumbleTimer = gRumbleTimer;
        gRumbleTimer = rumbleTimer > duration ? rumbleTimer : duration;
    }
}

void setJoypadDisabled(void) {
    joypadDisabled = 1;
}

void padSetStickRepeatDelay(int delay) {
    gPadMenuStickRepeatDelay = delay;
}

u32 buttonGetDisabled(int port) {
    return ~gPadButtonMask[port];
}

void buttonDisable(int port, u32 mask) {
    gPadButtonMask[port] &= ~mask;
}

void padClearAnalogInputY(int port) {
    gPadMenuStickYSign[port] = 0;
}

void padClearAnalogInputX(int port) {
    gPadMenuStickXSign[port] = 0;
}

void padGetAnalogInput(int port, s8* x, s8* y) {
    if (joypadDisabled != 0 || port > 0 || gDvdErrorPauseActive != 0) {
        *x = 0;
        *y = 0;
        return;
    }
    *x = gPadMenuStickXSign[port];
    *y = gPadMenuStickYSign[port];
}

s8 padGetCY(int port) {
    PADStatus* statuses;

    if (port > 0) {
        return 0;
    }
    if (joypadDisabled != 0 || gDvdErrorPauseActive != 0) {
        return 0;
    }
    statuses = gPadStatuses[0];
    return statuses[gPadStatusBufferIndex * 4 + port].substickY;
}

s8 padGetCX(int port) {
    PADStatus* statuses;

    if (port > 0) {
        return 0;
    }
    if (joypadDisabled != 0 || gDvdErrorPauseActive != 0) {
        return 0;
    }
    statuses = gPadStatuses[0];
    return statuses[gPadStatusBufferIndex * 4 + port].substickX;
}

s8 padGetStickY(int port) {
    PADStatus* statuses;

    if (port > 0) {
        return 0;
    }
    if (joypadDisabled != 0 || gDvdErrorPauseActive != 0) {
        return 0;
    }
    statuses = gPadStatuses[0];
    return statuses[gPadStatusBufferIndex * 4 + port].stickY;
}

s8 padGetStickX(int port) {
    PADStatus* statuses;

    if (port > 0) {
        return 0;
    }
    if (joypadDisabled != 0 || gDvdErrorPauseActive != 0) {
        return 0;
    }
    statuses = gPadStatuses[0];
    return statuses[gPadStatusBufferIndex * 4 + port].stickX;
}

u8 padGetLTrigger(int port) {
    PADStatus* statuses;

    if (joypadDisabled != 0 || gDvdErrorPauseActive != 0) {
        return 0;
    }
    statuses = gPadStatuses[0];
    return statuses[gPadStatusBufferIndex * 4 + port].triggerLeft;
}

u8 padGetRTrigger(int port) {
    PADStatus* statuses;

    if (joypadDisabled != 0 || gDvdErrorPauseActive != 0) {
        return 0;
    }
    statuses = gPadStatuses[0];
    return statuses[gPadStatusBufferIndex * 4 + port].triggerRight;
}

u16 padGetTriggersPressed(int port) {
    if (port > 0) {
        port = 0;
    }
    if (joypadDisabled != 0 || gDvdErrorPauseActive != 0) {
        return 0;
    }
    return gPadTriggersPressed[port];
}

u16 padGetTriggers(int port) {
    if (port > 0) {
        port = 0;
    }
    if (joypadDisabled != 0 || gDvdErrorPauseActive != 0) {
        return 0;
    }
    return gPadTriggers[port];
}

u32 getButtonsJustPressedIfNotBusy(int port) {
    if (port > 0) {
        return 0;
    }
    if (gDvdErrorPauseActive != 0) {
        return 0;
    }
    if (joypadDisabled != 0) {
        return -1;
    }
    return gPadButtonsReleased[port] & gPadButtonMask[port];
}

u32 getButtonsJustPressed(int port) {
    if (port > 0) {
        return 0;
    }
    if (joypadDisabled != 0 || gDvdErrorPauseActive != 0) {
        return 0;
    }
    return gPadButtonsJustPressed[port] & gPadButtonMask[port];
}

u32 getNewInputs(int port) {
    if (port > 0) {
        return 0;
    }
    return gPadButtonsHeld[port];
}

u32 getButtonsHeld(int port) {
    if (port > 0) {
        return 0;
    }
    if (joypadDisabled != 0 || gDvdErrorPauseActive != 0) {
        return 0;
    }
    return gPadButtonsHeld[port] & gPadButtonMask[port];
}

void doNothing_endOfFrame(void) {
}
void padUpdate(void) {
    u32* padStateBlock[1];
    PADStatus* currentStatus;
    s8* prevStickY;
    s8* prevStickX;
    s8* repeatY;
    s8* repeatX;
    s8* analogY;
    s8* analogX;
    u32* previousButtons;
    u32* currentButtons;
    u32* releasedButtons;
    u32* pressedButtons;
    u16* prevTriggers;
    u16* triggers;
    u16* triggersReleased;
    u16* triggersPressed;
    const PADStatus* prevPad;
    PADStatus* readPad;
    s32 i;
    PADStatus* statuses;
    int sx;
    int sy;
    u8 useprev;

    padStateBlock[0] = gPadButtonsPrevious;
    prevPad = (PADStatus*)((u8*)(padStateBlock[0] + 0x10) + gPadStatusBufferIndex * 0x30);
    gPadStatusBufferIndex ^= 1;
    readPad = (PADStatus*)((u8*)(padStateBlock[0] + 0x10) + gPadStatusBufferIndex * 0x30);
    if (PADRead(readPad) == PAD_ERR_TRANSFER) {
        return;
    }
    PADClamp(readPad);
    if (rumbleEnabled != 0) {
        if (gRumbleTimer > 0.0f) {
            gRumbleTimer -= timeDelta;
            if (gRumbleTimer <= 0.0f) {
                if (rumbleEnabled != 0) {
                    PADControlMotor(0, PAD_MOTOR_STOP);
                    gRumbleTimer = 0.0f;
                }
            }
        }
    }
    useprev = 0;
    joypadDisabled = 0;

    i = 0;
    currentStatus = readPad;
    prevStickY = gPadLastStickY;
    prevStickX = gPadLastStickX;
    repeatY = gPadMenuStickYHoldTimer;
    repeatX = gPadMenuStickXHoldTimer;
    analogY = gPadMenuStickYSign;
    analogX = gPadMenuStickXSign;
    previousButtons = padStateBlock[0];
    currentButtons = padStateBlock[0] + 4;
    releasedButtons = padStateBlock[0] + 8;
    pressedButtons = padStateBlock[0] + 12;
    prevTriggers = gPadPrevTriggers;
    triggers = gPadTriggers;
    triggersReleased = gPadTriggersReleased;
    triggersPressed = gPadTriggersPressed;
    statuses = (PADStatus*)((u8*)padStateBlock[0] + 0x40);

    for (; i < 4; i++) {
        if (currentStatus->err == PAD_ERR_NO_CONTROLLER) {
            *prevStickY = 0;
            *prevStickX = 0;
            *repeatY = 0;
            *repeatX = 0;
            *analogY = 0;
            *analogX = 0;
            *previousButtons = 0;
            *currentButtons = 0;
            *releasedButtons = 0;
            *pressedButtons = 0;
            *prevTriggers = 0;
            *triggers = 0;
            *triggersReleased = 0;
            *triggersPressed = 0;
            memset(statuses, 0, sizeof(PADStatus));
            memset((u8*)(padStateBlock[0] + 0x10) + (i + 4) * 0xc, 0, sizeof(PADStatus));
            gPadResetMask |= PAD_CHAN0_BIT >> i;
            currentStatus->err = PAD_ERR_NO_CONTROLLER;
        } else if ((u8)(currentStatus->err + 3) <= 1 || gPadReadReady == 0) {
            memcpy(currentStatus, prevPad, sizeof(PADStatus));
            useprev = 1;
        } else {
            *currentButtons = currentStatus->button;
            if (currentStatus->substickY < -40) {
                *currentButtons |= PAD_BUTTON_CSTICK_DOWN;
            }
            if (currentStatus->substickY > 40) {
                *currentButtons |= PAD_BUTTON_CSTICK_UP;
            }
            if (currentStatus->substickX < -40) {
                *currentButtons |= PAD_BUTTON_CSTICK_LEFT;
            }
            if (currentStatus->substickX > 40) {
                *currentButtons |= PAD_BUTTON_CSTICK_RIGHT;
            }
            *pressedButtons = *currentButtons & (*currentButtons ^ *previousButtons);
            *releasedButtons = *previousButtons & (*currentButtons ^ *previousButtons);
            *previousButtons = *currentButtons;

            *triggers = 0;
            if (currentStatus->triggerRight > 10) {
                *triggers |= PAD_ANALOG_TRIGGER_R;
            }
            if (currentStatus->triggerLeft > 10) {
                *triggers |= PAD_ANALOG_TRIGGER_L;
            }
            *triggersPressed = *triggers & (*triggers ^ *prevTriggers);
            *triggersReleased = *prevTriggers & (*triggers ^ *prevTriggers);
            *prevTriggers = *triggers;

            sx = currentStatus->stickX;
            sy = currentStatus->stickY;
            *analogX = 0;
            *analogY = 0;
            if (sx < -35 && *prevStickX >= -35) {
                *analogX = -1;
                *repeatX = 0;
            }
            if (sx > 35 && *prevStickX <= 35) {
                *analogX = 1;
                *repeatX = 0;
            }
            if (sy < -35 && *prevStickY >= -35) {
                *analogY = -1;
                *repeatY = 0;
            }
            if (sy > 35 && *prevStickY <= 35) {
                *analogY = 1;
                *repeatY = 0;
            }
            *prevStickY = sy;
            sy = *prevStickY;
            if (sy < -35) {
                (*repeatY)++;
            } else if (sy > 35) {
                (*repeatY)++;
            } else {
                *repeatY = 0;
            }
            if (*repeatY > gPadMenuStickRepeatDelay) {
                *prevStickY = 0;
                *repeatY = 0;
            }
            *prevStickX = sx;
            sx = *prevStickX;
            if (sx < -35) {
                (*repeatX)++;
            } else if (sx > 35) {
                (*repeatX)++;
            } else {
                *repeatX = 0;
            }
            if (*repeatX > gPadMenuStickRepeatDelay) {
                *prevStickX = 0;
                *repeatX = 0;
            }
            gPadButtonMask[i] = -1;
        }

        currentStatus++;
        prevStickY++;
        prevStickX++;
        repeatY++;
        repeatX++;
        analogY++;
        analogX++;
        previousButtons++;
        currentButtons++;
        releasedButtons++;
        pressedButtons++;
        prevTriggers++;
        triggers++;
        triggersReleased++;
        triggersPressed++;
        statuses++;
        prevPad++;
    }

    if (gPadResetMask != 0) {
        if (PADReset(gPadResetMask) != 0) {
            gPadResetMask = 0;
        }
    }
    if (useprev != 0) {
        gPadStatusBufferIndex ^= 1;
    }
    gPadReadReady = 0;
}

void setRumbleEnabled(u8 enabled) {
    rumbleEnabled = enabled;
}

int initControllers(void) {
    PadStateBlock* base[1];
    s8* prevStickY;
    s8* prevStickX;
    s8* repeatY;
    s8* repeatX;
    s8* analogY;
    s8* analogX;
    u32* previousButtons;
    u32* currentButtons;
    u32* buttonsReleased;
    u32* buttonsPressed;
    u16* prevTriggers;
    u16* triggers;
    u16* triggersReleased;
    u16* triggersPressed;
    PADStatus* statuses;
    u8* secondStatus;
    s32 i;

    base[0] = (PadStateBlock*)gPadButtonsPrevious;
    gPadResetMask = 0xF0000000;
    PADInit();
    PADRecalibrate(gPadResetMask);
    if (PADReset(gPadResetMask) != 0) {
        gPadResetMask = 0;
    }

    i = 0;
    prevStickY = gPadLastStickY;
    prevStickX = gPadLastStickX;
    repeatY = gPadMenuStickYHoldTimer;
    repeatX = gPadMenuStickXHoldTimer;
    analogY = gPadMenuStickYSign;
    analogX = gPadMenuStickXSign;
    previousButtons = base[0]->previousButtons;
    currentButtons = base[0]->currentButtons;
    buttonsReleased = base[0]->releasedButtons;
    buttonsPressed = base[0]->pressedButtons;
    prevTriggers = gPadPrevTriggers;
    triggers = gPadTriggers;
    triggersReleased = gPadTriggersReleased;
    triggersPressed = gPadTriggersPressed;
    statuses = base[0]->statusBuffers[0];

    for (; i < 4; i++) {
        *prevStickY = 0;
        *prevStickX = 0;
        *repeatY = 0;
        *repeatX = 0;
        *analogY = 0;
        *analogX = 0;
        *previousButtons = 0;
        *currentButtons = 0;
        *buttonsReleased = 0;
        *buttonsPressed = 0;
        *prevTriggers = 0;
        *triggers = 0;
        *triggersReleased = 0;
        *triggersPressed = 0;
        memset(statuses, 0, sizeof(PADStatus));
        secondStatus = (u8*)base[0];
        secondStatus += (i + 4) * sizeof(PADStatus);
        memset(secondStatus + 0x40, 0, sizeof(PADStatus));

        prevStickY++;
        prevStickX++;
        repeatY++;
        repeatX++;
        analogY++;
        analogX++;
        previousButtons++;
        currentButtons++;
        buttonsReleased++;
        buttonsPressed++;
        prevTriggers++;
        triggers++;
        triggersReleased++;
        triggersPressed++;
        statuses++;
        secondStatus++;
    }

    gPadStatusBufferIndex = 0;
    rumbleEnabled = 1;
    PADControlMotor(0, PAD_MOTOR_STOP_HARD);
    gRumbleTimer = 0.0f;
    return 0;
}

u32 gPadButtonMask[4] = {0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF};

PADStatus gPadStatuses[2][4];
u32 gPadButtonsJustPressed[4];
u32 gPadButtonsReleased[4];
u32 gPadButtonsHeld[4];
u32 gPadButtonsPrevious[4];
