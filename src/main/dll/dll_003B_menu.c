/*
 * menu (DLL 0x3B) - a small horizontal item-selector menu built by the
 * game text/HUD layer.
 *
 * Callers register items one at a time (Menu_func05 / Menu_func06): each
 * appends to the running item count (lbl_803DD8F0) and accumulated width
 * (lbl_803DD8F2), and the entry whose index matches the requested default
 * becomes the selected result id (lbl_803DD8F5). Menu_func03 / Menu_func04
 * reset the list before a build pass.
 *
 * Menu_func08 polls the menu each frame: it advances a wrap-around scroll
 * timer (lbl_803DD8EC against the lbl_803E21D8 window), reads the analog
 * stick to step the caller's selection index (wrapping at 0 / item count),
 * and once armed (lbl_803DD8E8) returns the selected id on A/Start (subject
 * to GameBit 0x44F) or the cancel id (lbl_803DD8F4) on B. It bails while the
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

s8 lbl_803DD8F5;  /* selected result id */
s8 lbl_803DD8F4;  /* cancel result id */
s16 lbl_803DD8F2; /* accumulated item width */
s8 lbl_803DD8F0;  /* item count */
f32 lbl_803DD8EC; /* scroll timer */
s8 lbl_803DD8E8;  /* armed flag (ignore input for one frame after build) */
extern f32 lbl_803E21D8; /* scroll timer wrap period */


s32 Menu_func0B(void)
{
    return lbl_803DD8F0;
}
#pragma peephole off
void Menu_func0A(int v)
{
    lbl_803DD8E8 = v;
}
#pragma peephole reset
void Menu_func09_nop(void)
{
}
#pragma scheduling off
#pragma peephole off
int Menu_func08(int* sel)
{
    s8 yInput;
    s8 xInput;
    int input;
    f32 timer;

    if (getHudHiddenFrameCount() != 0)
    {
        return -1;
    }
    timer = lbl_803DD8EC + timeDelta;
    lbl_803DD8EC = timer;
    if (timer > lbl_803E21D8)
    {
        lbl_803DD8EC = timer - lbl_803E21D8;
    }
    padGetAnalogInputS8(0, &yInput, &xInput);
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
        *sel = lbl_803DD8F0 - 1;
    }
    if (*sel >= lbl_803DD8F0)
    {
        *sel = 0;
    }
    if (lbl_803DD8E8 != 0)
    {
        input = getButtonsJustPressed(0);
        if (((input & PAD_ACCEPT_MASK) != 0) && (mainGetBit(GAMEBIT_MenuRelated044F) == 0))
        {
            return lbl_803DD8F5;
        }
        if ((input & PAD_BUTTON_B) != 0)
        {
            return lbl_803DD8F4;
        }
    }
    lbl_803DD8E8 = 1;
    return -1;
}
#pragma peephole reset
#pragma scheduling reset
#pragma peephole off
void Menu_func07(int v)
{
    lbl_803DD8F4 = v;
}
#pragma peephole reset
#pragma scheduling off
#pragma peephole off
void Menu_func06(int resultId, int unused2, int unused3, int itemWidth, int defaultIndex)
{
    if (defaultIndex == lbl_803DD8F0)
    {
        lbl_803DD8F5 = resultId;
    }
    lbl_803DD8F2 = (s16)((s32)lbl_803DD8F2 + itemWidth);
    lbl_803DD8F0++;
}

void Menu_func05(int resultId, int unused2, int itemWidth, int defaultIndex)
{
    if (defaultIndex == lbl_803DD8F0)
    {
        lbl_803DD8F5 = resultId;
    }
    lbl_803DD8F2 = (s16)((s32)lbl_803DD8F2 + itemWidth);
    lbl_803DD8F0++;
}
#pragma peephole reset
#pragma peephole off
void Menu_func04(int unused, int v)
{
    getScreenResolution();
    lbl_803DD8F2 = v;
    lbl_803DD8F0 = 0;
    lbl_803DD8F4 = -1;
}
#pragma peephole reset
#pragma peephole off
void Menu_func03(int v)
{
    lbl_803DD8F2 = v;
    lbl_803DD8F0 = 0;
    lbl_803DD8F4 = -1;
}
#pragma peephole reset
#pragma scheduling reset
void Menu_release(void)
{
}
void Menu_initialise(void)
{
    lbl_803DD8F0 = 0;
    lbl_803DD8F2 = 0;
    lbl_803DD8F4 = 0;
    lbl_803DD8F5 = 0;
    lbl_803DD8E8 = 0;
}

u32 lbl_8031C168[16] = {0x00000000,           0x00000000,           0x00000000,       0x000b0000,
                        (u32)Menu_initialise, (u32)Menu_release,    0x00000000,       (u32)Menu_func03,
                        (u32)Menu_func04,     (u32)Menu_func05,     (u32)Menu_func06, (u32)Menu_func07,
                        (u32)Menu_func08,     (u32)Menu_func09_nop, (u32)Menu_func0A, (u32)Menu_func0B};
