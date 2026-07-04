/*
 * C-menu item-select SFX dispatcher.
 *
 * cMenuPlaySelectedItemSfx maps the just-activated entry id (gCMenuActivatedId)
 * to a per-entry UI sound and plays it limited from the menu object. It is
 * called from cMenuRun's tricky branch, where gCMenuActivatedId is the Tricky
 * command index (0-5) and the sounds (0x3f7-0x3fc) are Fox's voice clips for
 * each command. Used by the C-menu code in dll 0x00 (gameui).
 */
#include "ghidra_import.h"

#pragma scheduling off

extern s16 gCMenuActivatedId;
/* u16 sfxId is load-bearing: retail masks the arg (clrlwi r4,r4,16) at this
 * call site, unlike the int-sfxId decl in sfx.h/engine_shared.h. */
extern u32 Sfx_PlayFromObjectLimited(u32 obj, u16 sfxId, int limit);

void cMenuPlaySelectedItemSfx(int obj)
{
    int sfx = 0;
    switch (gCMenuActivatedId)
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
        Sfx_PlayFromObjectLimited(obj, sfx, 1);
    }
}
