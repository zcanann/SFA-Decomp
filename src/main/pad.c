#include "main/pad.h"
#include "global.h"
#include "main/fileio.h"
#include "main/frame_timing.h"
#include "main/gameloop_api.h"
#include "dolphin/pad.h"
#include "string.h"

u8 gPadMenuStickRepeatDelay = 5;

/* Synthesized C-stick-as-direction bits OR'd into the extended button word. */
#define PAD_BUTTON_CSTICK_UP    0x10000
#define PAD_BUTTON_CSTICK_DOWN  0x20000
#define PAD_BUTTON_CSTICK_LEFT  0x40000
#define PAD_BUTTON_CSTICK_RIGHT 0x80000

PADStatus gPadStatuses[2 * PAD_MAX_CONTROLLERS];
STATIC_ASSERT(sizeof(gPadStatuses) == 0x60);
u32 gPadButtonsJustPressed[PAD_MAX_CONTROLLERS];
u32 gPadButtonsReleased[PAD_MAX_CONTROLLERS];
u32 gPadButtonsHeld[PAD_MAX_CONTROLLERS];
u32 gPadButtonsPrevious[PAD_MAX_CONTROLLERS];

u8 gPadStatusBufferIndex;
s8 gPadLastStickX[PAD_MAX_CONTROLLERS];
s8 gPadLastStickY[PAD_MAX_CONTROLLERS];
s8 gPadMenuStickXHoldTimer[PAD_MAX_CONTROLLERS];
s8 gPadMenuStickYHoldTimer[PAD_MAX_CONTROLLERS];
s8 gPadMenuStickXSign[PAD_MAX_CONTROLLERS];
s8 gPadMenuStickYSign[PAD_MAX_CONTROLLERS];
u16 gPadTriggersPressed[PAD_MAX_CONTROLLERS];
u16 gPadTriggersReleased[PAD_MAX_CONTROLLERS];
u16 gPadTriggers[PAD_MAX_CONTROLLERS];
u16 gPadPrevTriggers[PAD_MAX_CONTROLLERS];
u32 gPadResetMask;
f32 gRumbleTimer;
u8 rumbleEnabled;
u8 joypadDisabled;

u32 gPadButtonMask[PAD_MAX_CONTROLLERS] = {0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF};

int initControllers(void) {
    s32 i;

    gPadResetMask = 0xF0000000;
    PADInit();
    PADRecalibrate(gPadResetMask);
    if (PADReset(gPadResetMask) != 0) {
        gPadResetMask = 0;
    }

    for (i = 0; i < PAD_MAX_CONTROLLERS; i++) {
        gPadLastStickY[i] = 0;
        gPadLastStickX[i] = 0;
        gPadMenuStickYHoldTimer[i] = 0;
        gPadMenuStickXHoldTimer[i] = 0;
        gPadMenuStickYSign[i] = 0;
        gPadMenuStickXSign[i] = 0;
        gPadButtonsPrevious[i] = 0;
        gPadButtonsHeld[i] = 0;
        gPadButtonsReleased[i] = 0;
        gPadButtonsJustPressed[i] = 0;
        gPadPrevTriggers[i] = 0;
        gPadTriggers[i] = 0;
        gPadTriggersReleased[i] = 0;
        gPadTriggersPressed[i] = 0;
        memset(&gPadStatuses[i], 0, sizeof(PADStatus));
        memset(&gPadStatuses[i + PAD_MAX_CONTROLLERS], 0, sizeof(PADStatus));
    }

    gPadStatusBufferIndex = 0;
    rumbleEnabled = 1;
    PADControlMotor(0, PAD_MOTOR_STOP_HARD);
    gRumbleTimer = 0.0f;
    return 0;
}

void setRumbleEnabled(u8 enabled) {
    rumbleEnabled = enabled;
}

void padUpdate(void) {
    const PADStatus* previousStatuses;
    PADStatus* currentStatuses;
    s32 port;
    int stickX;
    int stickY;
    u8 usePreviousStatuses;

    previousStatuses = &gPadStatuses[gPadStatusBufferIndex * PAD_MAX_CONTROLLERS];
    gPadStatusBufferIndex ^= 1;
    currentStatuses = &gPadStatuses[gPadStatusBufferIndex * PAD_MAX_CONTROLLERS];
    if (PADRead(currentStatuses) == PAD_ERR_TRANSFER) {
        return;
    }
    PADClamp(currentStatuses);
    if (rumbleEnabled != 0) {
        if (gRumbleTimer > 0.0f) {
            gRumbleTimer -= timeDelta;
            if (gRumbleTimer <= 0.0f) {
                stopRumble();
            }
        }
    }
    usePreviousStatuses = 0;
    joypadDisabled = 0;

    for (port = 0; port < PAD_MAX_CONTROLLERS; port++) {
        if (currentStatuses[port].err == PAD_ERR_NO_CONTROLLER) {
            gPadLastStickY[port] = 0;
            gPadLastStickX[port] = 0;
            gPadMenuStickYHoldTimer[port] = 0;
            gPadMenuStickXHoldTimer[port] = 0;
            gPadMenuStickYSign[port] = 0;
            gPadMenuStickXSign[port] = 0;
            gPadButtonsPrevious[port] = 0;
            gPadButtonsHeld[port] = 0;
            gPadButtonsReleased[port] = 0;
            gPadButtonsJustPressed[port] = 0;
            gPadPrevTriggers[port] = 0;
            gPadTriggers[port] = 0;
            gPadTriggersReleased[port] = 0;
            gPadTriggersPressed[port] = 0;
            memset(&gPadStatuses[port], 0, sizeof(PADStatus));
            memset(&gPadStatuses[port + PAD_MAX_CONTROLLERS], 0, sizeof(PADStatus));
            gPadResetMask |= PAD_CHAN0_BIT >> port;
            currentStatuses[port].err = PAD_ERR_NO_CONTROLLER;
        } else if ((u8)(currentStatuses[port].err + 3) <= 1 || gPadReadReady == 0) {
            memcpy(&currentStatuses[port], &previousStatuses[port], sizeof(PADStatus));
            usePreviousStatuses = 1;
        } else {
            gPadButtonsHeld[port] = currentStatuses[port].button;
            if (currentStatuses[port].substickY < -40) {
                gPadButtonsHeld[port] |= PAD_BUTTON_CSTICK_DOWN;
            }
            if (currentStatuses[port].substickY > 40) {
                gPadButtonsHeld[port] |= PAD_BUTTON_CSTICK_UP;
            }
            if (currentStatuses[port].substickX < -40) {
                gPadButtonsHeld[port] |= PAD_BUTTON_CSTICK_LEFT;
            }
            if (currentStatuses[port].substickX > 40) {
                gPadButtonsHeld[port] |= PAD_BUTTON_CSTICK_RIGHT;
            }
            gPadButtonsJustPressed[port] = gPadButtonsHeld[port] & (gPadButtonsHeld[port] ^ gPadButtonsPrevious[port]);
            gPadButtonsReleased[port] = gPadButtonsPrevious[port] & (gPadButtonsHeld[port] ^ gPadButtonsPrevious[port]);
            gPadButtonsPrevious[port] = gPadButtonsHeld[port];

            gPadTriggers[port] = 0;
            if (currentStatuses[port].triggerRight > 10) {
                gPadTriggers[port] |= PAD_TRIGGER_R;
            }
            if (currentStatuses[port].triggerLeft > 10) {
                gPadTriggers[port] |= PAD_TRIGGER_L;
            }
            gPadTriggersPressed[port] = gPadTriggers[port] & (gPadTriggers[port] ^ gPadPrevTriggers[port]);
            gPadTriggersReleased[port] = gPadPrevTriggers[port] & (gPadTriggers[port] ^ gPadPrevTriggers[port]);
            gPadPrevTriggers[port] = gPadTriggers[port];

            stickX = currentStatuses[port].stickX;
            stickY = currentStatuses[port].stickY;
            gPadMenuStickXSign[port] = 0;
            gPadMenuStickYSign[port] = 0;
            if (stickX < -35 && gPadLastStickX[port] >= -35) {
                gPadMenuStickXSign[port] = -1;
                gPadMenuStickXHoldTimer[port] = 0;
            }
            if (stickX > 35 && gPadLastStickX[port] <= 35) {
                gPadMenuStickXSign[port] = 1;
                gPadMenuStickXHoldTimer[port] = 0;
            }
            if (stickY < -35 && gPadLastStickY[port] >= -35) {
                gPadMenuStickYSign[port] = -1;
                gPadMenuStickYHoldTimer[port] = 0;
            }
            if (stickY > 35 && gPadLastStickY[port] <= 35) {
                gPadMenuStickYSign[port] = 1;
                gPadMenuStickYHoldTimer[port] = 0;
            }
            gPadLastStickY[port] = stickY;
            stickY = gPadLastStickY[port];
            if (stickY < -35) {
                gPadMenuStickYHoldTimer[port]++;
            } else if (stickY > 35) {
                gPadMenuStickYHoldTimer[port]++;
            } else {
                gPadMenuStickYHoldTimer[port] = 0;
            }
            if (gPadMenuStickYHoldTimer[port] > gPadMenuStickRepeatDelay) {
                gPadLastStickY[port] = 0;
                gPadMenuStickYHoldTimer[port] = 0;
            }
            gPadLastStickX[port] = stickX;
            stickX = gPadLastStickX[port];
            if (stickX < -35) {
                gPadMenuStickXHoldTimer[port]++;
            } else if (stickX > 35) {
                gPadMenuStickXHoldTimer[port]++;
            } else {
                gPadMenuStickXHoldTimer[port] = 0;
            }
            if (gPadMenuStickXHoldTimer[port] > gPadMenuStickRepeatDelay) {
                gPadLastStickX[port] = 0;
                gPadMenuStickXHoldTimer[port] = 0;
            }
            gPadButtonMask[port] = -1;
        }
    }

    if (gPadResetMask != 0) {
        if (PADReset(gPadResetMask) != 0) {
            gPadResetMask = 0;
        }
    }
    if (usePreviousStatuses != 0) {
        gPadStatusBufferIndex ^= 1;
    }
    gPadReadReady = 0;
}

void doNothing_endOfFrame(void) {
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

u32 getNewInputs(int port) {
    if (port > 0) {
        return 0;
    }
    return gPadButtonsHeld[port];
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

u16 padGetTriggers(int port) {
    if (port > 0) {
        port = 0;
    }
    if (joypadDisabled != 0 || gDvdErrorPauseActive != 0) {
        return 0;
    }
    return gPadTriggers[port];
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

u8 padGetRTrigger(int port) {
    PADStatus* statuses;

    if (joypadDisabled != 0 || gDvdErrorPauseActive != 0) {
        return 0;
    }
    statuses = gPadStatuses;
    return statuses[gPadStatusBufferIndex * PAD_MAX_CONTROLLERS + port].triggerRight;
}

u8 padGetLTrigger(int port) {
    PADStatus* statuses;

    if (joypadDisabled != 0 || gDvdErrorPauseActive != 0) {
        return 0;
    }
    statuses = gPadStatuses;
    return statuses[gPadStatusBufferIndex * PAD_MAX_CONTROLLERS + port].triggerLeft;
}

s8 padGetStickX(int port) {
    PADStatus* statuses;

    if (port > 0) {
        return 0;
    }
    if (joypadDisabled != 0 || gDvdErrorPauseActive != 0) {
        return 0;
    }
    statuses = gPadStatuses;
    return statuses[gPadStatusBufferIndex * PAD_MAX_CONTROLLERS + port].stickX;
}

s8 padGetStickY(int port) {
    PADStatus* statuses;

    if (port > 0) {
        return 0;
    }
    if (joypadDisabled != 0 || gDvdErrorPauseActive != 0) {
        return 0;
    }
    statuses = gPadStatuses;
    return statuses[gPadStatusBufferIndex * PAD_MAX_CONTROLLERS + port].stickY;
}

s8 padGetCX(int port) {
    PADStatus* statuses;

    if (port > 0) {
        return 0;
    }
    if (joypadDisabled != 0 || gDvdErrorPauseActive != 0) {
        return 0;
    }
    statuses = gPadStatuses;
    return statuses[gPadStatusBufferIndex * PAD_MAX_CONTROLLERS + port].substickX;
}

s8 padGetCY(int port) {
    PADStatus* statuses;

    if (port > 0) {
        return 0;
    }
    if (joypadDisabled != 0 || gDvdErrorPauseActive != 0) {
        return 0;
    }
    statuses = gPadStatuses;
    return statuses[gPadStatusBufferIndex * PAD_MAX_CONTROLLERS + port].substickY;
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

void padClearAnalogInputX(int port) {
    gPadMenuStickXSign[port] = 0;
}

void padClearAnalogInputY(int port) {
    gPadMenuStickYSign[port] = 0;
}

void buttonDisable(int port, u32 mask) {
    gPadButtonMask[port] &= ~mask;
}

u32 buttonGetDisabled(int port) {
    return ~gPadButtonMask[port];
}

void padSetStickRepeatDelay(int delay) {
    gPadMenuStickRepeatDelay = delay;
}

void setJoypadDisabled(void) {
    joypadDisabled = 1;
}

void doRumble(f32 duration) {
    if (rumbleEnabled != 0 && getGameState() == 1) {
        f32 rumbleTimer;

        PADControlMotor(0, PAD_MOTOR_RUMBLE);
        rumbleTimer = gRumbleTimer;
        gRumbleTimer = rumbleTimer > duration ? rumbleTimer : duration;
    }
}

void stopRumble(void) {
    if (rumbleEnabled != 0) {
        PADControlMotor(0, PAD_MOTOR_STOP);
        gRumbleTimer = 0.0f;
    }
}

void stopRumble2(void) {
    if (rumbleEnabled != 0) {
        PADControlMotor(0, PAD_MOTOR_STOP_HARD);
        gRumbleTimer = 0.0f;
    }
}