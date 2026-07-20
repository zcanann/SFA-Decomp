/*
 * menu (DLL 0x3B) - a small horizontal item-selector menu built by the
 * game text/HUD layer.
 *
 * Callers register items one at a time (Menu_addItem / Menu_addItemEx): each
 * appends to the running item count (gMenuItemCount) and accumulated width
 * (gMenuTotalWidth), and the entry whose index matches the requested default
 * becomes the selected result id (gMenuSelectedId). Menu_reset / Menu_open
 * reset the list before a build pass.
 *
 * Menu_poll polls the menu each frame: it advances a wrap-around scroll
 * timer (gMenuScrollTimer against the lbl_803E21D8 window), reads the analog
 * stick to step the caller's selection index (wrapping at 0 / item count),
 * and once armed (gMenuArmed) returns the selected id on A/Start (subject
 * to GameBit 0x44F) or the cancel id (gMenuCancelId) on B. It bails while the
 * HUD is hidden.
 */
#include "main/dll/dll_003B_menu.h"
#include "main/dll/dll_0000_gameui.h"
#include "main/gamebits.h"
#include "main/pad.h"
#include "main/gameloop_api.h"
#include "main/dll/pausemenu.h"
#include "track/intersect_api.h"
#include "main/frame_timing.h"

#define PAD_BUTTON_A     0x100
#define PAD_BUTTON_B     0x200
#define PAD_BUTTON_START 0x1000
#define PAD_ACCEPT_MASK  (PAD_BUTTON_A | PAD_BUTTON_START)

s8 gMenuSelectedId;  /* selected result id */
s8 gMenuCancelId;    /* cancel result id */
s16 gMenuTotalWidth; /* accumulated item width */
s8 gMenuItemCount;   /* item count */
f32 gMenuScrollTimer; /* scroll timer */
s8 gMenuArmed;       /* armed flag (ignore input for one frame after build) */
extern f32 lbl_803E21D8; /* scroll timer wrap period */

s32 Menu_getItemCount(void)
{
    return gMenuItemCount;
}
void Menu_setArmed(int v)
{
    gMenuArmed = v;
}
void Menu_func09_nop(void)
{
}
int Menu_poll(int* sel)
{
    s8 yInput;
    s8 xInput;
    int input;
    f32 timer;

    if (getHudHiddenFrameCount() != 0)
    {
        return -1;
    }
    timer = gMenuScrollTimer + timeDelta;
    gMenuScrollTimer = timer;
    if (timer > lbl_803E21D8)
    {
        gMenuScrollTimer = timer - lbl_803E21D8;
    }
    padGetAnalogInput(0, &yInput, &xInput);
    if (xInput < 0)
    {
        *sel = *sel + 1;
    }
    else if (xInput > 0)
    {
        *sel = *sel - 1;
    }
    if (*sel < 0)
    {
        *sel = gMenuItemCount - 1;
    }
    if (*sel >= gMenuItemCount)
    {
        *sel = 0;
    }
    if (gMenuArmed != 0)
    {
        input = getButtonsJustPressed(0);
        if (((input & PAD_ACCEPT_MASK) != 0) && (mainGetBit(GAMEBIT_MenuRelated044F) == 0))
        {
            return gMenuSelectedId;
        }
        if ((input & PAD_BUTTON_B) != 0)
        {
            return gMenuCancelId;
        }
    }
    gMenuArmed = 1;
    return -1;
}
void Menu_setCancelId(int v)
{
    gMenuCancelId = v;
}
void Menu_addItemEx(int resultId, int unused2, int unused3, int itemWidth, int defaultIndex)
{
    if (defaultIndex == gMenuItemCount)
    {
        gMenuSelectedId = resultId;
    }
    gMenuTotalWidth = (s16)((s32)gMenuTotalWidth + itemWidth);
    gMenuItemCount++;
}

void Menu_addItem(int resultId, int unused2, int itemWidth, int defaultIndex)
{
    if (defaultIndex == gMenuItemCount)
    {
        gMenuSelectedId = resultId;
    }
    gMenuTotalWidth = (s16)((s32)gMenuTotalWidth + itemWidth);
    gMenuItemCount++;
}
void Menu_open(int unused, int v)
{
    getScreenResolution();
    gMenuTotalWidth = v;
    gMenuItemCount = 0;
    gMenuCancelId = -1;
}
void Menu_reset(int v)
{
    gMenuTotalWidth = v;
    gMenuItemCount = 0;
    gMenuCancelId = -1;
}
void Menu_release(void)
{
}
void Menu_initialise(void)
{
    gMenuItemCount = 0;
    gMenuTotalWidth = 0;
    gMenuCancelId = 0;
    gMenuSelectedId = 0;
    gMenuArmed = 0;
}

u32 lbl_8031C168[16] = {0x00000000,           0x00000000,           0x00000000,       0x000b0000,
                        (u32)Menu_initialise, (u32)Menu_release,    0x00000000,       (u32)Menu_reset,
                        (u32)Menu_open,       (u32)Menu_addItem,    (u32)Menu_addItemEx, (u32)Menu_setCancelId,
                        (u32)Menu_poll,       (u32)Menu_func09_nop, (u32)Menu_setArmed, (u32)Menu_getItemCount};
