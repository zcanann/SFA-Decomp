#include "main/engine_shared.h"

#define PAD_MOTOR_STOP 0
#define PAD_MOTOR_RUMBLE 1
#define PAD_MOTOR_STOP_HARD 2

#define PAD_ERR_NO_CONTROLLER -1
#define PAD_ERR_TRANSFER -3

#define PAD_CHAN0_BIT 0x80000000

typedef struct PadStateBlock {
    u32 held[4];        // 0x00
    u32 buttons[4];     // 0x10
    u32 released[4];    // 0x20
    u32 pressed[4];     // 0x30
    PadStatusLite status[8]; // 0x40
} PadStateBlock;

u32 gPadStateBlock[4];
u32 gPadButtonsHeld[4];
u32 lbl_803398D0[4];
u32 gPadButtonsJustPressed[4];
u8 gPadStatuses[0x60];

void doNothing_endOfFrame(void)
{
}

void setJoypadDisabled(void)
{
    joypadDisabled = 1;
}

void padFn_80014b18(int value)
{
    gPadStickRepeatDelay = value;
}

u32 buttonGetDisabled(int port)
{
    return ~gPadButtonMask[port];
}

void buttonDisable(int port, u32 mask)
{
    gPadButtonMask[port] &= ~mask;
}

void padClearAnalogInputY(int port)
{
    (&gPadAnalogY)[port] = 0;
}

void padClearAnalogInputX(int port)
{
    (&gPadAnalogX)[port] = 0;
}

void stopRumble2(void)
{
    if (rumbleEnabled != 0)
    {
        PADControlMotor(0, PAD_MOTOR_STOP_HARD);
        gRumbleTimer = lbl_803DE6E8;
    }
}

void stopRumble(void)
{
    if (rumbleEnabled != 0)
    {
        PADControlMotor(0, PAD_MOTOR_STOP);
        gRumbleTimer = lbl_803DE6E8;
    }
}

void doRumble(f32 duration)
{
    if (rumbleEnabled != 0 && getGameState() == 1)
    {
        f32 rumbleTimer;

        PADControlMotor(0, PAD_MOTOR_RUMBLE);
        rumbleTimer = gRumbleTimer;
        gRumbleTimer = (rumbleTimer > duration) ? rumbleTimer : duration;
    }
}

void setRumbleEnabled(u8 enabled)
{
    rumbleEnabled = enabled;
}

void padGetAnalogInput(int port, u8* x, u8* y)
{
    if (joypadDisabled != 0 || port > 0 || gDvdErrorPauseActive != 0)
    {
        *x = 0;
        *y = 0;
        return;
    }
    *x = (&gPadAnalogX)[port];
    *y = (&gPadAnalogY)[port];
}

u8 padGetCY(int port)
{
    PadStatusLite* statuses;

    if (port > 0)
    {
        return 0;
    }
    if (joypadDisabled != 0 || gDvdErrorPauseActive != 0)
    {
        return 0;
    }
    statuses = (PadStatusLite*)gPadStatuses;
    return statuses[gPadStatusToggle * 4 + port].substickY;
}

u8 padGetCX(int port)
{
    PadStatusLite* statuses;

    if (port > 0)
    {
        return 0;
    }
    if (joypadDisabled != 0 || gDvdErrorPauseActive != 0)
    {
        return 0;
    }
    statuses = (PadStatusLite*)gPadStatuses;
    return statuses[gPadStatusToggle * 4 + port].substickX;
}

u8 padGetStickY(int port)
{
    PadStatusLite* statuses;

    if (port > 0)
    {
        return 0;
    }
    if (joypadDisabled != 0 || gDvdErrorPauseActive != 0)
    {
        return 0;
    }
    statuses = (PadStatusLite*)gPadStatuses;
    return statuses[gPadStatusToggle * 4 + port].stickY;
}

u8 padGetStickX(int port)
{
    PadStatusLite* statuses;

    if (port > 0)
    {
        return 0;
    }
    if (joypadDisabled != 0 || gDvdErrorPauseActive != 0)
    {
        return 0;
    }
    statuses = (PadStatusLite*)gPadStatuses;
    return statuses[gPadStatusToggle * 4 + port].stickX;
}

u8 padGetLTrigger(int port)
{
    PadStatusLite* statuses;

    if (joypadDisabled != 0 || gDvdErrorPauseActive != 0)
    {
        return 0;
    }
    statuses = (PadStatusLite*)gPadStatuses;
    return statuses[gPadStatusToggle * 4 + port].triggerLeft;
}

u8 padGetRTrigger(int port)
{
    PadStatusLite* statuses;

    if (joypadDisabled != 0 || gDvdErrorPauseActive != 0)
    {
        return 0;
    }
    statuses = (PadStatusLite*)gPadStatuses;
    return statuses[gPadStatusToggle * 4 + port].triggerRight;
}

u16 getPadFn_80014d9c(int port)
{
    if (port > 0)
    {
        port = 0;
    }
    if (joypadDisabled != 0 || gDvdErrorPauseActive != 0)
    {
        return 0;
    }
    return (&gPadTriggersPressed)[port];
}

u16 getButtons_80014dd8(int port)
{
    if (port > 0)
    {
        port = 0;
    }
    if (joypadDisabled != 0 || gDvdErrorPauseActive != 0)
    {
        return 0;
    }
    return (&gPadTriggers)[port];
}

u32 getButtonsJustPressedIfNotBusy(int port)
{
    if (port > 0)
    {
        return 0;
    }
    if (gDvdErrorPauseActive != 0)
    {
        return 0;
    }
    if (joypadDisabled != 0)
    {
        return -1;
    }
    return lbl_803398D0[port] & gPadButtonMask[port];
}

u32 getButtonsJustPressed(int port)
{
    if (port > 0)
    {
        return 0;
    }
    if (joypadDisabled != 0 || gDvdErrorPauseActive != 0)
    {
        return 0;
    }
    return gPadButtonsJustPressed[port] & gPadButtonMask[port];
}

u32 getNewInputs(int port)
{
    if (port > 0)
    {
        return 0;
    }
    return gPadButtonsHeld[port];
}

u32 getButtonsHeld(int port)
{
    if (port > 0)
    {
        return 0;
    }
    if (joypadDisabled != 0 || gDvdErrorPauseActive != 0)
    {
        return 0;
    }
    return gPadButtonsHeld[port] & gPadButtonMask[port];
}

int initControllers(void)
{
    PadStateBlock* base;
    u8* prevStickY;
    u8* prevStickX;
    u8* repeatY;
    u8* repeatX;
    u8* analogY;
    u8* analogX;
    u32* heldButtons;
    u32* buttonsPressed;
    u32* buttonsReleased;
    u32* controlStick;
    u16* prevTriggers;
    u16* triggers;
    u16* triggersReleased;
    u16* triggersPressed;
    PadStatusLite* statuses;
    s32 i;

    base = (PadStateBlock*)gPadStateBlock;
    gPadResetMask = 0xF0000000;
    PADInit();
    PADRecalibrate(gPadResetMask);
    if (PADReset(gPadResetMask) != 0)
    {
        gPadResetMask = 0;
    }

    i = 0;
    prevStickY = &gPadPrevStickY;
    prevStickX = &gPadPrevStickX;
    repeatY = &gPadRepeatY;
    repeatX = &gPadRepeatX;
    analogY = &gPadAnalogY;
    analogX = &gPadAnalogX;
    heldButtons = base->held;
    buttonsPressed = base->buttons;
    buttonsReleased = base->released;
    controlStick = base->pressed;
    prevTriggers = &gPadPrevTriggers;
    triggers = &gPadTriggers;
    triggersReleased = &gPadTriggersReleased;
    triggersPressed = &gPadTriggersPressed;
    statuses = base->status;

    for (; i < 4; i++)
    {
        *prevStickY = 0;
        *prevStickX = 0;
        *repeatY = 0;
        *repeatX = 0;
        *analogY = 0;
        *analogX = 0;
        *heldButtons = 0;
        *buttonsPressed = 0;
        *buttonsReleased = 0;
        *controlStick = 0;
        *prevTriggers = 0;
        *triggers = 0;
        *triggersReleased = 0;
        *triggersPressed = 0;
        memset(statuses, 0, sizeof(PadStatusLite));
        memset((i + 4) * 0xc + 0x40 + (u8*)base, 0, sizeof(PadStatusLite));

        prevStickY++;
        prevStickX++;
        repeatY++;
        repeatX++;
        analogY++;
        analogX++;
        heldButtons++;
        buttonsPressed++;
        buttonsReleased++;
        controlStick++;
        prevTriggers++;
        triggers++;
        triggersReleased++;
        triggersPressed++;
        statuses++;
    }

    gPadStatusToggle = 0;
    rumbleEnabled = 1;
    PADControlMotor(0, PAD_MOTOR_STOP_HARD);
    gRumbleTimer = lbl_803DE6E8;
    return 0;
}

#pragma opt_common_subs off
void padUpdate(void)
{
    u32* padStateBlock;
    PadStatusLite* readPad;
    PadStatusLite* rp;
    PadStatusLite* statuses;
    PadStatusLite* prevPad;
    s8* prevStickY;
    s8* prevStickX;
    s8* repeatY;
    s8* repeatX;
    s8* analogY;
    s8* analogX;
    u32* heldRaw;
    u32* curBtn;
    u32* released;
    u32* pressed;
    u16* prevTriggers;
    u16* triggers;
    u16* triggersReleased;
    u16* triggersPressed;
    u32* buttonMask;
    int sx;
    int sy;
    u8 toggle;
    u8 other;
    u8 useprev;
    s32 i;

    padStateBlock = gPadStateBlock;
    toggle = gPadStatusToggle;
    prevPad = (PadStatusLite*)((u8*)padStateBlock + toggle * 0x30 + 0x40);
    other = toggle ^ 1;
    gPadStatusToggle = other;
    readPad = (PadStatusLite*)((u8*)padStateBlock + other * 0x30 + 0x40);
    if (PADRead(readPad) == PAD_ERR_TRANSFER)
    {
        return;
    }
    PADClamp(readPad);
    if (rumbleEnabled != 0)
    {
        if (gRumbleTimer > lbl_803DE6E8)
        {
            gRumbleTimer = gRumbleTimer - timeDelta;
            if (gRumbleTimer <= lbl_803DE6E8)
            {
                if (rumbleEnabled != 0)
                {
                    PADControlMotor(0, PAD_MOTOR_STOP);
                    gRumbleTimer = lbl_803DE6E8;
                }
            }
        }
    }
    useprev = 0;
    joypadDisabled = 0;

    i = 0;
    rp = readPad;
    prevStickY = (s8*)&gPadPrevStickY;
    prevStickX = (s8*)&gPadPrevStickX;
    repeatY = (s8*)&gPadRepeatY;
    repeatX = (s8*)&gPadRepeatX;
    analogY = (s8*)&gPadAnalogY;
    analogX = (s8*)&gPadAnalogX;
    heldRaw = padStateBlock;
    curBtn = padStateBlock + 4;
    released = padStateBlock + 8;
    pressed = padStateBlock + 12;
    prevTriggers = &gPadPrevTriggers;
    triggers = &gPadTriggers;
    triggersReleased = &gPadTriggersReleased;
    triggersPressed = &gPadTriggersPressed;
    statuses = (PadStatusLite*)((u8*)padStateBlock + 0x40);
    buttonMask = gPadButtonMask;

    for (; i < 4; i++)
    {
        if (rp->error == PAD_ERR_NO_CONTROLLER)
        {
            *prevStickY = 0;
            *prevStickX = 0;
            *repeatY = 0;
            *repeatX = 0;
            *analogY = 0;
            *analogX = 0;
            *heldRaw = 0;
            *curBtn = 0;
            *released = 0;
            *pressed = 0;
            *prevTriggers = 0;
            *triggers = 0;
            *triggersReleased = 0;
            *triggersPressed = 0;
            memset(statuses, 0, sizeof(PadStatusLite));
            memset((i + 4) * 0xc + 0x40 + (u8*)padStateBlock, 0, sizeof(PadStatusLite));
            gPadResetMask |= (u32)PAD_CHAN0_BIT >> i;
            rp->error = PAD_ERR_NO_CONTROLLER;
        }
        else if ((u8)(rp->error + 3) <= 1 || lbl_803DCCA5 == 0)
        {
            memcpy(rp, prevPad, sizeof(PadStatusLite));
            useprev = 1;
        }
        else
        {
            *curBtn = rp->buttons;
            if (rp->substickY < -40)
            {
                *curBtn |= 0x20000LL;
            }
            if (rp->substickY > 40)
            {
                *curBtn |= 0x10000LL;
            }
            if (rp->substickX < -40)
            {
                *curBtn |= 0x40000LL;
            }
            if (rp->substickX > 40)
            {
                *curBtn |= 0x80000LL;
            }
            *pressed = *curBtn & (*curBtn ^ *heldRaw);
            *released = *heldRaw & (*curBtn ^ *heldRaw);
            *heldRaw = *curBtn;

            *triggers = 0;
            if (rp->triggerRight > 10)
            {
                *triggers |= 0x20;
            }
            if (rp->triggerLeft > 10)
            {
                *triggers |= 0x40;
            }
            *triggersPressed = *triggers & (*triggers ^ *prevTriggers);
            *triggersReleased = *prevTriggers & (*triggers ^ *prevTriggers);
            *prevTriggers = *triggers;

            sx = rp->stickX;
            sy = rp->stickY;
            *analogX = 0;
            *analogY = 0;
            if (sx < -35 && *prevStickX >= -35)
            {
                *analogX = -1;
                *repeatX = 0;
            }
            if (sx > 35 && *prevStickX <= 35)
            {
                *analogX = 1;
                *repeatX = 0;
            }
            if (sy < -35 && *prevStickY >= -35)
            {
                *analogY = -1;
                *repeatY = 0;
            }
            if (sy > 35 && *prevStickY <= 35)
            {
                *analogY = 1;
                *repeatY = 0;
            }
            *prevStickY = sy;
            if (*prevStickY < -35)
            {
                (*repeatY)++;
            }
            else if (*prevStickY > 35)
            {
                (*repeatY)++;
            }
            else
            {
                *repeatY = 0;
            }
            if (*repeatY > gPadStickRepeatDelay)
            {
                *prevStickY = 0;
                *repeatY = 0;
            }
            *prevStickX = sx;
            if (*prevStickX < -35)
            {
                (*repeatX)++;
            }
            else if (*prevStickX > 35)
            {
                (*repeatX)++;
            }
            else
            {
                *repeatX = 0;
            }
            if (*repeatX > gPadStickRepeatDelay)
            {
                *prevStickX = 0;
                *repeatX = 0;
            }
            *buttonMask = -1;
        }

        rp++;
        prevStickY++;
        prevStickX++;
        repeatY++;
        repeatX++;
        analogY++;
        analogX++;
        heldRaw++;
        curBtn++;
        released++;
        pressed++;
        prevTriggers++;
        triggers++;
        triggersReleased++;
        triggersPressed++;
        statuses++;
        prevPad++;
        buttonMask++;
    }

    if (gPadResetMask != 0)
    {
        if (PADReset(gPadResetMask) != 0)
        {
            gPadResetMask = 0;
        }
    }
    if (useprev != 0)
    {
        gPadStatusToggle ^= 1;
    }
    lbl_803DCCA5 = 0;
}
#pragma opt_common_subs reset
