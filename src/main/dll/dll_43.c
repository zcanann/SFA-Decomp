/*
 * dll_43 - save-select "confirm slot" action (companion to the save-select
 * screen DLL 0x35).
 *
 * saveSelectSetSlot() is invoked from saveSelectScreen when the player
 * confirms a slot. Slot 0 is the "back" choice: if a save already exists
 * (lbl_803DB424) it returns to the choose-slot screen, otherwise it plays
 * the rotation sfx, kicks off screen transition 0x14, and arms the
 * pending-action flags (lbl_803DD6CC/CF). Any other slot starts a new
 * game: it flags the choice, plays the confirm sfx, runs transition 0x14,
 * tears down the four title-menu control sub-objects via vtable slot 7,
 * and records the chosen value (lbl_803DD6C4).
 *
 * The lbl_803DD6xx / lbl_803DB424 state words are shared with DLL 0x35
 * (its home TU); 0x23 here matches that TU's pending-action value.
 */
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/dll/dll_43.h"
#include "main/screen_transition.h"
#include "main/dll/dll_0035_saveselectscreen.h"
#include "main/audio/sfx_trigger_ids.h"



extern u8 lbl_803DB424;
extern TitleMenuControl* gTitleMenuControlInterface;
extern u8 lbl_803DD6C4;
extern u8 lbl_803DD6CC;
extern u8 lbl_803DD6CD;
extern s8 lbl_803DD6CF;

void saveSelectSetSlot(int slot, int value)
{
    if (slot == 0)
    {
        if (lbl_803DB424 != 0)
        {
            Sfx_PlayFromObject(0, SFXTRIG_menu_pause_down); /* back sfx (unnamed in sfx_ids.h) */
            saveSelectGoToChooseSlot(0);
        }
        else
        {
            Sfx_PlayFromObject(0, SFXsp_snrot1_c);
            (*gScreenTransitionInterface)->start(0x14, 5);
            lbl_803DD6CF = 0x23;
            lbl_803DD6CC = 1;
        }
    }
    else
    {
        lbl_803DD6CD = 1;
        Sfx_PlayFromObject(0, SFXTRIG_menu_pause_up); /* confirm sfx (unnamed in sfx_ids.h) */
        (*gScreenTransitionInterface)->start(0x14, 1);
        ((void (**)(int))gTitleMenuControlInterface->vtable)[7](0);
        ((void (**)(int))gTitleMenuControlInterface->vtable)[7](1);
        ((void (**)(int))gTitleMenuControlInterface->vtable)[7](2);
        ((void (**)(int))gTitleMenuControlInterface->vtable)[7](3);
        lbl_803DD6CF = 0x23;
        lbl_803DD6C4 = value;
    }
}
