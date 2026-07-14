/*
 * C-menu item-select SFX dispatcher.
 *
 * cMenuPlayTrickyCommandSfx maps the just-activated entry id (gCMenuActivatedId)
 * to a per-entry UI sound and plays it limited from the menu object. It is
 * called from cMenuRun's tricky branch, where gCMenuActivatedId is the Tricky
 * command index (0-5) and the sounds (0x3f7-0x3fc) are Fox's voice clips for
 * each command. Used by the C-menu code in dll 0x00 (gameui).
 */
#include "ghidra_import.h"
#include "main/audio/sfx_limited_object_api.h"
#include "main/dll/dll_8011d918.h"

#pragma scheduling off

extern s16 gCMenuActivatedId;

void cMenuPlayTrickyCommandSfx(int obj)
{
    int sfx = 0;
    switch (gCMenuActivatedId)
    {
    case 0:
        sfx = 0x3FB;
        break;
    case 5:
        sfx = 0x3FA;
        break;
    case 1:
        sfx = 0x3F8;
        break;
    case 4:
        sfx = 0x3F9;
        break;
    case 2:
        sfx = 0x3F7;
        break;
    case 3:
        sfx = 0x3FC;
        break;
    }
    if (sfx != 0)
    {
        Sfx_PlayFromObjectLimitedU32U16Legacy(obj, sfx, 1);
    }
}
