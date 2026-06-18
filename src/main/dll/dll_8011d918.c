/*
 * Menu item-select SFX dispatcher.
 *
 * cMenuPlaySelectedItemSfx maps the current menu-cursor row index
 * (lbl_803DD8C2) to a per-row UI sound and plays it limited from the
 * menu object. Used by the pause/menu code in dll 0x00 (baby_snowworm).
 */
#include "ghidra_import.h"

#pragma scheduling off

extern s16 lbl_803DD8C2;
extern u32 Sfx_PlayFromObjectLimited(u32 obj, u16 sfxId, int limit);

void cMenuPlaySelectedItemSfx(int obj)
{
    int sfx = 0;
    switch (lbl_803DD8C2)
    {
    case 0: sfx = 0x3FB;
        break;
    case 5: sfx = 0x3FA;
        break;
    case 1: sfx = 0x3F8;
        break;
    case 4: sfx = 0x3F9;
        break;
    case 2: sfx = 0x3F7;
        break;
    case 3: sfx = 0x3FC;
        break;
    }
    if (sfx != 0)
    {
        Sfx_PlayFromObjectLimited(obj, (u16)sfx, 1);
    }
}
