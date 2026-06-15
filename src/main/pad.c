#include "main/engine_shared.h"

void doNothing_endOfFrame(void)
{
}

void setJoypadDisabled(void)
{
    joypadDisabled = 1;
}

void padFn_80014b18(int value)
{
    lbl_803DB2A8 = (u8)value;
}

u32 buttonGetDisabled(int port)
{
    return ~lbl_802C6E50[port];
}

void buttonDisable(int port, u32 mask)
{
    lbl_802C6E50[port] &= ~mask;
}

void padClearAnalogInputY(int port)
{
    (&lbl_803DC934)[port] = 0;
}

void padClearAnalogInputX(int port)
{
    (&lbl_803DC938)[port] = 0;
}

void stopRumble2(void)
{
    if (rumbleEnabled != 0)
    {
        PADControlMotor(0, 2);
        lbl_803DC90C = lbl_803DE6E8;
    }
}

void stopRumble(void)
{
    if (rumbleEnabled != 0)
    {
        PADControlMotor(0, 0);
        lbl_803DC90C = lbl_803DE6E8;
    }
}

void doRumble(f32 duration)
{
    if (rumbleEnabled != 0 && getGameState() == 1)
    {
        f32 rumbleTimer;

        PADControlMotor(0, 1);
        rumbleTimer = lbl_803DC90C;
        lbl_803DC90C = (rumbleTimer > duration) ? rumbleTimer : duration;
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
    *x = (&lbl_803DC938)[port];
    *y = (&lbl_803DC934)[port];
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
    statuses = (PadStatusLite*)lbl_803398F0;
    return statuses[lbl_803DC94C * 4 + port].substickY;
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
    statuses = (PadStatusLite*)lbl_803398F0;
    return statuses[lbl_803DC94C * 4 + port].substickX;
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
    statuses = (PadStatusLite*)lbl_803398F0;
    return statuses[lbl_803DC94C * 4 + port].stickY;
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
    statuses = (PadStatusLite*)lbl_803398F0;
    return statuses[lbl_803DC94C * 4 + port].stickX;
}

u8 padGetLTrigger(int port)
{
    PadStatusLite* statuses;

    if (joypadDisabled != 0 || gDvdErrorPauseActive != 0)
    {
        return 0;
    }
    statuses = (PadStatusLite*)lbl_803398F0;
    return statuses[lbl_803DC94C * 4 + port].triggerLeft;
}

u8 padGetRTrigger(int port)
{
    PadStatusLite* statuses;

    if (joypadDisabled != 0 || gDvdErrorPauseActive != 0)
    {
        return 0;
    }
    statuses = (PadStatusLite*)lbl_803398F0;
    return statuses[lbl_803DC94C * 4 + port].triggerRight;
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
    return (&lbl_803DC92C)[port];
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
    return (&lbl_803DC91C)[port];
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
    return lbl_803398D0[port] & lbl_802C6E50[port];
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
    return lbl_803398E0[port] & lbl_802C6E50[port];
}

u32 getNewInputs(int port)
{
    if (port > 0)
    {
        return 0;
    }
    return lbl_803398C0[port];
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
    return lbl_803398C0[port] & lbl_802C6E50[port];
}

int initControllers(void)
{
    s32 i;
    u8* prevStickY;
    u8* prevStickX;
    u8* repeatY;
    u8* repeatX;
    u8* analogY;
    u8* analogX;
    u32* padStateBlock;
    u32* heldButtons;
    u32* buttonsPressed;
    u32* buttonsReleased;
    u16* prevTriggers;
    u16* triggers;
    u16* triggersReleased;
    u16* triggersPressed;
    PadStatusLite* statuses;

    padStateBlock = lbl_803398B0;
    statuses = (PadStatusLite*)((u8*)padStateBlock + 0x40);
    lbl_803DC910 = 0xF0000000;
    PADInit();
    PADRecalibrate(lbl_803DC910);
    if (PADReset(lbl_803DC910) != 0)
    {
        lbl_803DC910 = 0;
    }

    prevStickY = &lbl_803DC944;
    prevStickX = &lbl_803DC948;
    repeatY = &lbl_803DC93C;
    repeatX = &lbl_803DC940;
    analogY = &lbl_803DC934;
    analogX = &lbl_803DC938;
    heldButtons = padStateBlock;
    buttonsPressed = padStateBlock + 4;
    buttonsReleased = padStateBlock + 8;
    padStateBlock = padStateBlock + 12;
    prevTriggers = &lbl_803DC914;
    triggers = &lbl_803DC91C;
    triggersReleased = &lbl_803DC924;
    triggersPressed = &lbl_803DC92C;

    for (i = 0; i < 4; i++)
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
        *padStateBlock = 0;
        *prevTriggers = 0;
        *triggers = 0;
        *triggersReleased = 0;
        *triggersPressed = 0;
        memset(statuses, 0, sizeof(PadStatusLite));
        memset((u8*)lbl_803398B0 + (i + 4) * 0xc + 0x40, 0, sizeof(PadStatusLite));

        prevStickY++;
        prevStickX++;
        repeatY++;
        repeatX++;
        analogY++;
        analogX++;
        heldButtons++;
        buttonsPressed++;
        buttonsReleased++;
        padStateBlock++;
        prevTriggers++;
        triggers++;
        triggersReleased++;
        triggersPressed++;
        statuses++;
    }

    lbl_803DC94C = 0;
    rumbleEnabled = 1;
    PADControlMotor(0, 2);
    lbl_803DC90C = lbl_803DE6E8;
    return 0;
}

void padUpdate(void)
{
    u32* padStateBlock;
    PadStatusLite* readPad;
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

    padStateBlock = lbl_803398B0;
    toggle = lbl_803DC94C;
    prevPad = (PadStatusLite*)((u8*)padStateBlock + toggle * 0x30 + 0x40);
    other = toggle ^ 1;
    lbl_803DC94C = other;
    readPad = (PadStatusLite*)((u8*)padStateBlock + other * 0x30 + 0x40);
    if (PADRead(readPad) == -3)
    {
        return;
    }
    PADClamp(readPad);
    if (rumbleEnabled != 0)
    {
        if (lbl_803DC90C > lbl_803DE6E8)
        {
            lbl_803DC90C = lbl_803DC90C - timeDelta;
            if (lbl_803DC90C <= lbl_803DE6E8)
            {
                if (rumbleEnabled != 0)
                {
                    PADControlMotor(0, 0);
                    lbl_803DC90C = lbl_803DE6E8;
                }
            }
        }
    }
    useprev = 0;
    joypadDisabled = 0;

    prevStickY = (s8*)&lbl_803DC944;
    prevStickX = (s8*)&lbl_803DC948;
    repeatY = (s8*)&lbl_803DC93C;
    repeatX = (s8*)&lbl_803DC940;
    analogY = (s8*)&lbl_803DC934;
    analogX = (s8*)&lbl_803DC938;
    heldRaw = padStateBlock;
    curBtn = padStateBlock + 4;
    released = padStateBlock + 8;
    pressed = padStateBlock + 12;
    prevTriggers = &lbl_803DC914;
    triggers = &lbl_803DC91C;
    triggersReleased = &lbl_803DC924;
    triggersPressed = &lbl_803DC92C;
    statuses = (PadStatusLite*)((u8*)padStateBlock + 0x40);
    buttonMask = lbl_802C6E50;

    for (i = 0; i < 4; i++)
    {
        if (readPad->error == -1)
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
            memset((u8*)padStateBlock + (i + 4) * 0xc + 0x40, 0, sizeof(PadStatusLite));
            lbl_803DC910 |= 0x80000000U >> i;
            readPad->error = -1;
        }
        else if ((u8)(readPad->error + 3) <= 1 || lbl_803DCCA5 == 0)
        {
            memcpy(readPad, prevPad, sizeof(PadStatusLite));
            useprev = 1;
        }
        else
        {
            *curBtn = readPad->buttons;
            if (readPad->substickY < -40)
            {
                *curBtn |= 0x20000LL;
            }
            if (readPad->substickY > 40)
            {
                *curBtn |= 0x10000LL;
            }
            if (readPad->substickX < -40)
            {
                *curBtn |= 0x40000LL;
            }
            if (readPad->substickX > 40)
            {
                *curBtn |= 0x80000LL;
            }
            *pressed = *curBtn & (*curBtn ^ *heldRaw);
            *released = *heldRaw & (*curBtn ^ *heldRaw);
            *heldRaw = *curBtn;

            *triggers = 0;
            if (readPad->triggerRight > 10)
            {
                *triggers |= 0x20;
            }
            if (readPad->triggerLeft > 10)
            {
                *triggers |= 0x40;
            }
            *triggersPressed = *triggers & (*triggers ^ *prevTriggers);
            *triggersReleased = *prevTriggers & (*triggers ^ *prevTriggers);
            *prevTriggers = *triggers;

            sx = readPad->stickX;
            sy = readPad->stickY;
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
            if (*repeatY > lbl_803DB2A8)
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
            if (*repeatX > lbl_803DB2A8)
            {
                *prevStickX = 0;
                *repeatX = 0;
            }
            *buttonMask = -1;
        }

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
        readPad++;
        prevPad++;
        statuses++;
        buttonMask++;
    }

    if (lbl_803DC910 != 0)
    {
        if (PADReset(lbl_803DC910) != 0)
        {
            lbl_803DC910 = 0;
        }
    }
    if (useprev != 0)
    {
        lbl_803DC94C ^= 1;
    }
    lbl_803DCCA5 = 0;
}
