/*
 * dll_4d - language/misc front-end menu setup (UI DLL 0x4D).
 *
 * languageMenuInit() builds the "misc" sub-panel (lbl_8031ACB8) of the
 * options front-end: it tears down any previously-active panel, marks
 * panel 3 (misc) active (lbl_803DBA28), and creates the language menu
 * row through the title-menu item interface. When cheat 3 is unlocked
 * and not already shown (lbl_803DC968), it links in and creates a second
 * row reflecting that cheat's active state; otherwise that row is hidden.
 * The created rows are focused/laid out through the title-menu link
 * interface and the panel's render-stale countdown (lbl_803DD706) is
 * reset so the new layout draws.
 */
#include "main/dll/dll_4D.h"
#include "main/dll/DR/dr_shared.h"

/* misc-panel id stored in lbl_803DBA28 (see dll_0037_optionsscreen.c) */
#define OPTIONS_PANEL_MISC 3

/* the in-game cheat queried for the second menu row */
#define LANGUAGE_MENU_CHEAT_ID 3

/* TitleMenuTextEntry.flags: row is hidden / non-selectable */
#define TITLE_MENU_TEXT_ENTRY_HIDDEN 0x4000

/* title-menu item-interface vtable slot: create a menu row, returns widget */
#define TITLE_MENU_ITEM_CREATE_ROW 3

/* title-menu link-interface vtable slots */
#define TITLE_MENU_LINK_RESET_PANEL 2
#define TITLE_MENU_LINK_LAYOUT_ROWS 1
#define TITLE_MENU_LINK_FOCUS_ROW 8

/* lbl_803DBA28 active-panel id and lbl_803DD706 render-stale countdown
   are owned by dll_0037_optionsscreen.c */
extern MenuPanelGroup lbl_8031ACB8;
extern u8 lbl_803DBA28;
extern TitleMenuControl* gTitleMenuLinkInterface;
extern TitleMenuControl* gTitleMenuItemInterface;
extern u8 lbl_803DD706;
extern u8* lbl_803DD708; /* save-file struct; [2] = subtitles enabled */
extern int lbl_803A87D0[8]; /* created menu-row widgets of the active panel */

extern int saveFileStruct_isCheatActive(int cheatId);
extern int isCheatUnlocked(int cheatId);

void languageMenuInit(void)
{
    MenuPanelGroup* panel;

    if ((s8)lbl_803DBA28 != -1)
    {
        ((void (**)(void))gTitleMenuLinkInterface->vtable)[TITLE_MENU_LINK_RESET_PANEL]();
    }
    lbl_803DBA28 = OPTIONS_PANEL_MISC;

    panel = &lbl_8031ACB8;
    lbl_803A87D0[0] = ((int (**)(int, int, int, int, s16))gTitleMenuItemInterface->vtable)[TITLE_MENU_ITEM_CREATE_ROW](
        0x36b, 0x22, 0, 1, (s16)(lbl_803DD708[2] == 0));

    if (isCheatUnlocked(LANGUAGE_MENU_CHEAT_ID) != 0 && lbl_803DC968 == 0)
    {
        panel->entries[panel->count - 2].pad18[3] = panel->count - 1;
        panel->entries[panel->count - 1].flags &= ~TITLE_MENU_TEXT_ENTRY_HIDDEN;

        lbl_803A87D0[1] = ((int (**)(int, int, int, int, s16))gTitleMenuItemInterface->vtable)[TITLE_MENU_ITEM_CREATE_ROW](
            0x36b, 0x23, 0, 1, (s16)(saveFileStruct_isCheatActive(LANGUAGE_MENU_CHEAT_ID) == 0));
    }
    else
    {
        panel->entries[panel->count - 2].pad18[3] = -1;
        panel->entries[panel->count - 1].flags |= TITLE_MENU_TEXT_ENTRY_HIDDEN;
    }

    ((void (**)(int, int))gTitleMenuLinkInterface->vtable)[TITLE_MENU_LINK_FOCUS_ROW](lbl_803A87D0[0], 1);

    ((void (**)(TitleMenuTextEntry*, int, int, int, int, int, int, int, int, int, int, int))
        gTitleMenuLinkInterface->vtable)[TITLE_MENU_LINK_LAYOUT_ROWS](
        panel->entries, panel->count, 0, 0, 0, 0, 0x14, 0xc8,
        0xff, 0xff, 0xff, 0xff);

    lbl_803DD706 = 2;
}
