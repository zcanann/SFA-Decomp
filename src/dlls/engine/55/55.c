#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_4D.h"
#include "main/dll/debug/prof.h"
#include "main/dll/dll_0037_optionsscreen.h"
#include "main/pad.h"
#include "main/screen_transition.h"
#include "main/dll/dll_003C_link.h"
#include "main/dll/dll_003D_titlemenuitem.h"
#include "main/dll/dll_0004_dummy04.h"
#include "main/dll/savedata_struct.h"
#include "main/textrender_api.h"
#include "dolphin/os/OSRtc.h"
#include "main/rcp_dolphin_state_api.h"
#include "main/model_engine.h"
#include "main/dll/dll_02C0_front_api.h"
#include "main/dll/front_game_text_box_api.h"
#include "main/frame_timing.h"
#include "main/gametext_box_api.h"
#include "main/gametext_show_api.h"
#include "main/lightmap_render_control_api.h"
#include "main/dll/FRONT/title_menu.h"
#include "main/dll/dll_0015_curves.h"
#include "main/gametext_color_api.h"
#include "dlls/object_descriptor.h"
#include "main/audio/audio_control_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_object_api.h"
#include "main/dll/dll_02C0_front.h"
#include "main/lightmap_api.h"
#include "main/rcp_dolphin_render_api.h"
#include "main/dll/dll_4E.h"

typedef struct OptionsScreenPanelConfig {
    u16* items;
    u32 reserved;
    u16 itemLayout;
    u16 selectionTextId;
    u16 headingTextId;
    u16 padding;
} OptionsScreenPanelConfig;

extern OptionsScreenPanelConfig gOptionsPanelTable[4];

TitleMenuItem* gOptionsMenuItems[8];

/*
 * dll_4e - options-menu setting callbacks (audio panel, gameplay panel,
 * submenu selector).
 *
 * Each callback is driven by the title-menu item widgets in
 * gOptionsMenuItems[]: the widget at the option index (the menu row) is
 * queried through the gTitleMenuItemInterface vtable - slot 0x2c tests
 * whether the value changed, slot 0x24 reads the current value, slot
 * 0x28 sets a value, slot 0x10 frees the widget. The action arg selects
 * the menu action (CLOSE vs SELECT); CLOSE plays a back sfx and kicks
 * the screen transition into the next menu state.
 *
 * - applyAudioSetting: sound mode, music/sfx/voice volume, reset to
 *   defaults (reloads the saved volumes from gOptionsSaveData).
 * - applyGameplaySetting: widescreen, rumble, roll credits, colour
 *   filter.
 * - openSelectedSubmenu: general / audio / language panels.
 */

#define OPTIONS_MENU_ACTION_CLOSE      0
#define OPTIONS_MENU_ACTION_SELECT     1
#define OPTIONS_MENU_TRANSITION_FRAMES 0x14
#define OPTIONS_MENU_TRANSITION_MODE   5
#define OPTIONS_MENU_NEXT_STATE        0x23
#define OPTIONS_MENU_VOLUME_STEP       10
#define OPTIONS_MENU_ITEM_COUNT        8

#define OPTIONS_SFX_VOLUME_PREVIEW 0x3b9
#define OPTIONS_SFX_CONFIRM        0x418

#define AUDIO_OPTION_SOUND_MODE     0
#define AUDIO_OPTION_MUSIC_VOLUME   1
#define AUDIO_OPTION_SFX_VOLUME     2
#define AUDIO_OPTION_VOICE_VOLUME   3
#define AUDIO_OPTION_RESET_DEFAULTS 4
#define AUDIO_OPTION_EXTRA          5

#define GAMEPLAY_OPTION_WIDESCREEN   0
#define GAMEPLAY_OPTION_RUMBLE       1
#define GAMEPLAY_OPTION_CREDITS      2
#define GAMEPLAY_OPTION_COLOR_FILTER 3

#define OPTIONS_SUBMENU_GENERAL  0
#define OPTIONS_SUBMENU_AUDIO    2
#define OPTIONS_SUBMENU_LANGUAGE 3

extern s8 gOptionsActivePanel;
extern int lbl_803DD6FC;
extern s8 gOptionsExitCountdown;
extern s8 gOptionsExitRequested;
extern s8 gOptionsLayoutRefreshFrames;

void optionsMenu_applyAudioSetting(int action, int option)
{
    int value;

    if (gOptionsMenuItems[option] != NULL && gTitleMenuItemInterface->vtable->isChanged(gOptionsMenuItems[option]) != 0)
    {
        switch (option)
        {
        case AUDIO_OPTION_SOUND_MODE:
            audioSetSoundMode((u8)gTitleMenuItemInterface->vtable->getValue(gOptionsMenuItems[option]), 1);
            break;
        case AUDIO_OPTION_SFX_VOLUME:
            value = gTitleMenuItemInterface->vtable->getValue(gOptionsMenuItems[option]);
            audioSetVolumes((u8)value, OPTIONS_MENU_VOLUME_STEP, 0, 1, 0);
            break;
        case AUDIO_OPTION_MUSIC_VOLUME:
            value = gTitleMenuItemInterface->vtable->getValue(gOptionsMenuItems[option]);
            audioSetVolumes((u8)value, OPTIONS_MENU_VOLUME_STEP, 1, 0, 0);
            value = gTitleMenuItemInterface->vtable->getValue(gOptionsMenuItems[option]);
            gTitleMenuControlInterface->vtable->func0D(value); /* set music control value */
            break;
        case AUDIO_OPTION_VOICE_VOLUME:
            value = gTitleMenuItemInterface->vtable->getValue(gOptionsMenuItems[option]);
            audioSetVolumes((u8)value, OPTIONS_MENU_VOLUME_STEP, 0, 0, 1);
            break;
        case AUDIO_OPTION_EXTRA:
            lbl_803DD6FC = gTitleMenuItemInterface->vtable->getValue(gOptionsMenuItems[option]);
            break;
        }
    }
    if ((gOptionsMenuItems[option] == NULL) ||
        ((option != AUDIO_OPTION_SFX_VOLUME) && (option != AUDIO_OPTION_MUSIC_VOLUME) &&
         (option != AUDIO_OPTION_VOICE_VOLUME)))
    {
        Sfx_StopFromObject(0, OPTIONS_SFX_VOLUME_PREVIEW);
    }
    if (action == OPTIONS_MENU_ACTION_CLOSE)
    {
        Sfx_PlayFromObject(0, SFXTRIG_wmap_name);
        (*gScreenTransitionInterface)->start(OPTIONS_MENU_TRANSITION_FRAMES, OPTIONS_MENU_TRANSITION_MODE);
        gOptionsExitCountdown = OPTIONS_MENU_NEXT_STATE;
        gOptionsExitRequested = 1;
    }
    else if ((action == OPTIONS_MENU_ACTION_SELECT) && (option == AUDIO_OPTION_RESET_DEFAULTS))
    {
        saveFileStruct_resetVolumes();
        gTitleMenuItemInterface->vtable->setValue(gOptionsMenuItems[AUDIO_OPTION_MUSIC_VOLUME],
                                                   gOptionsSaveData->musicVolume);
        gTitleMenuItemInterface->vtable->setValue(gOptionsMenuItems[AUDIO_OPTION_SFX_VOLUME], gOptionsSaveData->sfxVolume);
        gTitleMenuItemInterface->vtable->setValue(gOptionsMenuItems[AUDIO_OPTION_VOICE_VOLUME],
                                                   gOptionsSaveData->speechVolume);
        value = gTitleMenuItemInterface->vtable->getValue(gOptionsMenuItems[AUDIO_OPTION_MUSIC_VOLUME]);
        audioSetVolumes((u8)value, OPTIONS_MENU_VOLUME_STEP, 0, 1, 0);
        value = gTitleMenuItemInterface->vtable->getValue(gOptionsMenuItems[AUDIO_OPTION_SFX_VOLUME]);
        audioSetVolumes((u8)value, OPTIONS_MENU_VOLUME_STEP, 1, 0, 0);
        value = gTitleMenuItemInterface->vtable->getValue(gOptionsMenuItems[AUDIO_OPTION_VOICE_VOLUME]);
        audioSetVolumes((u8)value, OPTIONS_MENU_VOLUME_STEP, 0, 0, 1);
        Sfx_PlayFromObject(0, OPTIONS_SFX_CONFIRM);
    }
}

void optionsMenu_applyGameplaySetting(int action, int option)
{
    int z[2];
    u8 newState;

    if (gOptionsMenuItems[option] != NULL && gTitleMenuItemInterface->vtable->isChanged(gOptionsMenuItems[option]) != 0)
    {
        switch (option)
        {
        case GAMEPLAY_OPTION_WIDESCREEN:
            setWidescreen((u8)gTitleMenuItemInterface->vtable->getValue(gOptionsMenuItems[option]));
            break;
        case GAMEPLAY_OPTION_RUMBLE:
            newState = !gTitleMenuItemInterface->vtable->getValue(gOptionsMenuItems[option]);
            if (newState == 0)
            {
                stopRumble2();
            }
            setRumbleEnabled(newState);
            if (newState != 0)
            {
                doRumble(20.0f);
            }
            break;
        case GAMEPLAY_OPTION_CREDITS:
            if (gTitleMenuItemInterface->vtable->getValue(gOptionsMenuItems[option]) == 0)
            {
                creditsStart();
                if (gOptionsActivePanel != -1)
                {
                    gTitleMenuLinkInterface->vtable->free();
                    gOptionsActivePanel = -1;
                }
                z[0] = 0;
                z[1] = z[0];
                for (; z[0] < OPTIONS_MENU_ITEM_COUNT; z[0]++)
                {
                    if (gOptionsMenuItems[z[0]] != NULL)
                    {
                        gTitleMenuItemInterface->vtable->free(gOptionsMenuItems[z[0]]);
                        gOptionsMenuItems[z[0]] = (TitleMenuItem*)z[1];
                    }
                }
            }
            break;
        case GAMEPLAY_OPTION_COLOR_FILTER:
            Rcp_SetColorFilterEnabled(gTitleMenuItemInterface->vtable->getValue(gOptionsMenuItems[option]));
            break;
        }
    }
    if (action == OPTIONS_MENU_ACTION_CLOSE)
    {
        Sfx_PlayFromObject(0, SFXTRIG_wmap_name);
        (*gScreenTransitionInterface)->start(OPTIONS_MENU_TRANSITION_FRAMES, OPTIONS_MENU_TRANSITION_MODE);
        gOptionsExitCountdown = OPTIONS_MENU_NEXT_STATE;
        gOptionsExitRequested = 1;
    }
}

int optionsMenu_openSelectedSubmenu(int action, int option)
{
    if (action == OPTIONS_MENU_ACTION_SELECT)
    {
        switch (option)
        {
        case OPTIONS_SUBMENU_GENERAL:
            optionsMenu_openGeneralPanel();
            return 1;
        case OPTIONS_SUBMENU_AUDIO:
            optionsMenu_openAudioPanel();
            return 1;
        case OPTIONS_SUBMENU_LANGUAGE:
            languageMenuInit();
            return 1;
        }
    }
    else if (action == OPTIONS_MENU_ACTION_CLOSE)
    {
        Sfx_PlayFromObject(0, SFXTRIG_wmap_name);
        (*gScreenTransitionInterface)->start(OPTIONS_MENU_TRANSITION_FRAMES, OPTIONS_MENU_TRANSITION_MODE);
        gOptionsExitCountdown = OPTIONS_MENU_NEXT_STATE;
        gOptionsExitRequested = 1;
    }
    return 0;
}

/*
 * dll_4d - language/misc front-end menu setup (UI DLL 0x4D).
 *
 * languageMenuInit() builds the "misc" sub-panel (gOptionsPanelTable) of the
 * options front-end: it tears down any previously-active panel, marks
 * panel 3 (misc) active (gOptionsActivePanel), and creates the language menu
 * row through the title-menu item interface. When cheat 3 is unlocked
 * and the system font encoding is not SJIS, it links in and creates a second
 * row reflecting that cheat's active state; otherwise that row is hidden.
 * The created rows are focused through the title-menu item interface,
 * laid out through the title-menu link interface, and the panel's
 * render-stale countdown (gOptionsLayoutRefreshFrames) is reset so the new layout draws.
 */

/* misc-panel id stored in gOptionsActivePanel (see dll_0037_optionsscreen.c) */
#define OPTIONS_PANEL_MISC 3

/* the in-game cheat queried for the second menu row */
#define LANGUAGE_MENU_CHEAT_ID CHEAT_DINO_LANGUAGE

/* gOptionsActivePanel active-panel id and gOptionsLayoutRefreshFrames render-stale countdown
   are owned by dll_0037_optionsscreen.c */

void languageMenuInit(void)
{
    MenuPanelGroup* panel;

    if (gOptionsActivePanel != -1)
    {
        gTitleMenuLinkInterface->vtable->free();
    }
    gOptionsActivePanel = OPTIONS_PANEL_MISC;

    panel = (MenuPanelGroup*)gOptionsPanelTable;
    gOptionsMenuItems[0] =
        gTitleMenuItemInterface->vtable->createWithWindow(0x36b, 0x22, 0, 1,
                                                         (s16)(gOptionsSaveData->subtitlesEnabled == 0));

    if (isCheatUnlocked(LANGUAGE_MENU_CHEAT_ID) != 0 && gGameTextFontIsSjis == 0)
    {
        panel->entries[panel->count - 2].downLink = panel->count - 1;
        panel->entries[panel->count - 1].flags &= ~TITLE_MENU_TEXT_ENTRY_HIDDEN;

        gOptionsMenuItems[1] = gTitleMenuItemInterface->vtable->createWithWindow(
            0x36b, 0x23, 0, 1, (s16)(saveFileStruct_isCheatActive(LANGUAGE_MENU_CHEAT_ID) == 0));
    }
    else
    {
        panel->entries[panel->count - 2].downLink = -1;
        panel->entries[panel->count - 1].flags |= TITLE_MENU_TEXT_ENTRY_HIDDEN;
    }

    gTitleMenuItemInterface->vtable->setEnabled(gOptionsMenuItems[0], 1);

    gTitleMenuLinkInterface->vtable->setup(panel->entries, panel->count, 0, NULL, 0, 0, 0x14, 0xc8, 0xff, 0xff, 0xff,
                                           0xff);

    gOptionsLayoutRefreshFrames = 2;
}

/*
 * prof - title-screen Options menu panel builders.
 *
 * Two entry points populate the Options sub-menus through the title-menu
 * link/item interfaces (gTitleMenuLink/Item). openAudioPanel builds the
 * Audio panel (surround/stereo/mono toggle, music/sfx/voice sliders, and
 * a cheat-gated extra entry); openGeneralPanel builds the General panel,
 * unlocking option/cheat entries based on isCheatUnlocked() and toggling
 * the per-entry "disabled" flag (0x4000) accordingly.
 *
 * gOptionsActivePanel tracks which panel is currently open (-1 = none); a switch
 * away first tears down the previous link (slot +8). Built item handles
 * are cached in gOptionsMenuItems[]. gOptionsLayoutRefreshFrames is set to 2 by both builders;
 * its exact role is unconfirmed.
 */

typedef struct OptionsMenuPanels
{
    u8 pad00[0x10];
    TitleMenuTextEntry* audioEntries;
    u32 unk_14;
    u8 audioCount;
    u8 pad19[0x20 - 0x19];
    TitleMenuTextEntry* optionEntries;
    u32 unk_24;
    u8 optionCount;
} OptionsMenuPanels;

void optionsMenu_openAudioPanel(void)
{
    OptionsMenuPanels* panels;
    TitleMenuItem* item;

    if (gOptionsActivePanel != -1)
    {
        gTitleMenuLinkInterface->vtable->free();
    }
    gOptionsActivePanel = 1;
    panels = (OptionsMenuPanels*)gOptionsPanelTable;

    if (isCheatUnlocked(2) != 0)
    {
        panels->audioEntries[4].downLink = 5;
        panels->audioEntries[5].flags = (u16)(panels->audioEntries[5].flags & ~TITLE_MENU_TEXT_ENTRY_HIDDEN);
        panels->audioEntries[5].upLink = 4;
    }
    else
    {
        panels->audioEntries[4].downLink = -1;
        panels->audioEntries[5].flags = (u16)(panels->audioEntries[5].flags | TITLE_MENU_TEXT_ENTRY_HIDDEN);
    }

    gTitleMenuLinkInterface->vtable->setup(panels->audioEntries, panels->audioCount, 0, NULL, 0, 0, 0x14, 0xc8, 0xff,
                                           0xff, 0xff, 0xff);

    if (OSGetSoundMode() == 1)
    {
        item = gTitleMenuItemInterface->vtable->createWithWindow(0x36c, 0x22, 0, 3, gOptionsSaveData->soundMode);
    }
    else
    {
        item = gTitleMenuItemInterface->vtable->createWithWindow(0x36c, 0x22, 0, 3, 2);
    }
    gOptionsMenuItems[0] = item;
    gOptionsMenuItems[1] =
        gTitleMenuItemInterface->vtable->createWithText(0x124, 0xb2, 0, 0x7f, gOptionsSaveData->musicVolume, 0x3e);
    gOptionsMenuItems[2] =
        gTitleMenuItemInterface->vtable->createWithText(0x124, 0xcc, 0, 0x7f, gOptionsSaveData->sfxVolume, 0x3e);
    gOptionsMenuItems[3] =
        gTitleMenuItemInterface->vtable->createWithText(0x124, 0xe6, 0, 0x7f, gOptionsSaveData->speechVolume, 0x3e);
    gOptionsMenuItems[3]->flags = (u8)(gOptionsMenuItems[3]->flags | 0x40);
    gOptionsMenuItems[4] = NULL;
    gOptionsMenuItems[5] = NULL;

    if (isCheatUnlocked(2) != 0)
    {
        gOptionsMenuItems[5] = gTitleMenuItemInterface->vtable->createWithWindow(
            0x3cb, 0x27, 0, (s16)(Music_GetTrackCount() - 1), 0);
        gOptionsMenuItems[5]->flags = (u8)(gOptionsMenuItems[5]->flags | 0x80);
    }

    gTitleMenuItemInterface->vtable->setEnabled(gOptionsMenuItems[0], 1);
    gOptionsLayoutRefreshFrames = 2;
}

void optionsMenu_openGeneralPanel(void)
{
    OptionsMenuPanels* panels;
    int lastUnlocked;
    int entryIndex;
    int cheatId;
    TitleMenuItem** slot[1];
    int cheatId2;
    int entryIndex2;
    int lastUnlocked2;

    if (gOptionsActivePanel != -1)
    {
        gTitleMenuLinkInterface->vtable->free();
    }
    gOptionsActivePanel = 2;
    panels = (OptionsMenuPanels*)gOptionsPanelTable;

    lastUnlocked = -1;
    cheatId = 3;
    entryIndex = 3;
    do
    {
        if (isCheatUnlocked((u8)(cheatId - 2)) != 0)
        {
            panels->optionEntries[entryIndex - 1].downLink = cheatId;
            panels->optionEntries[entryIndex].flags &= ~TITLE_MENU_TEXT_ENTRY_HIDDEN;
            lastUnlocked = cheatId;
        }
        else
        {
            panels->optionEntries[entryIndex - 1].downLink = lastUnlocked;
            panels->optionEntries[entryIndex].flags |= TITLE_MENU_TEXT_ENTRY_HIDDEN;
        }
        entryIndex--;
        cheatId--;
    } while (cheatId > 1);

    lastUnlocked2 = 1;
    cheatId2 = 2;
    entryIndex2 = 2;
    do
    {
        if (isCheatUnlocked((u8)(cheatId2 - 2)) != 0)
        {
            panels->optionEntries[entryIndex2].upLink = lastUnlocked2;
            panels->optionEntries[entryIndex2].flags &= ~TITLE_MENU_TEXT_ENTRY_HIDDEN;
            lastUnlocked2 = cheatId2;
        }
        entryIndex2++;
        cheatId2++;
    } while (cheatId2 < 4);

    gTitleMenuLinkInterface->vtable->setup(panels->optionEntries, panels->optionCount, 0, NULL, 0, 0, 0x14, 0xc8, 0xff,
                                           0xff, 0xff, 0xff);

    gOptionsMenuItems[0] =
        gTitleMenuItemInterface->vtable->createWithWindow(0x366, 0x22, 0, 1, gOptionsSaveData->widescreenEnabled);
    gOptionsMenuItems[1] =
        gTitleMenuItemInterface->vtable->createWithWindow(0x36b, 0x23, 0, 1,
                                                         (s16)(gOptionsSaveData->rumbleEnabled == 0));
    slot[0] = gOptionsMenuItems;

    cheatId = 0;
    do
    {
        if (isCheatUnlocked((u8)cheatId) != 0)
        {
            if (cheatId == CHEAT_SEPIA_MODE)
            {
                slot[0][2] = gTitleMenuItemInterface->vtable->createWithWindow(
                    0x507, cheatId + 0x24, 0, 1, Rcp_GetColorFilterEnabled());
            }
            else
            {
                slot[0][2] = gTitleMenuItemInterface->vtable->createWithWindow(
                    0x36b, cheatId + 0x24, 0, 1, (s16)(saveFileStruct_isCheatActive((u8)cheatId) == 0));
            }
        }
        slot[0]++;
        cheatId++;
    } while (cheatId <= 1);

    gTitleMenuItemInterface->vtable->setEnabled(gOptionsMenuItems[0], 1);
    gOptionsLayoutRefreshFrames = 2;
}

#define OPTIONSSCREEN_MENU_ITEM_COUNT 8

#define OPTIONSSCREEN_PANEL_NONE     (-1)
#define OPTIONSSCREEN_PANEL_TOP      0
#define OPTIONSSCREEN_PANEL_AUDIO    1
#define OPTIONSSCREEN_PANEL_GAMEPLAY 2
#define OPTIONSSCREEN_PANEL_MISC     3

s8 gOptionsActivePanel = -1;
s8 lbl_803DD70C;
SaveData* gOptionsSaveData;
s8 gOptionsLayoutRefreshFrames;
s8 gOptionsExitRequested;
s8 gOptionsExitCountdown;
int gOptionsLastSelectedRow;
int lbl_803DD6FC;
u8 lbl_803DD6F9;
u8 gOptionsRequestedPanel;

u16 gOptionsTopPanelEntries[90] = {
    0x035a, 0x0012, 0x0140, 0x00a4, 0x0000, 0x0140, 0x0034, 0x0000, 0xffff, 0xffff, 0x00c8, 0x0200, 0x0000, 0xff01, 0xffff, 0xff00,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x035c, 0x0013,
    0x0140, 0x0110, 0x0000, 0x0140, 0x00a0, 0x0000, 0xffff, 0xffff, 0x00c8, 0x0200, 0x0000, 0x01ff, 0xffff, 0xff00, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x035b, 0x0014, 0x0140, 0x00da,
    0x0000, 0x0140, 0x006a, 0x0000, 0xffff, 0xffff, 0x00c8, 0x0200, 0x0000, 0x0002, 0xffff, 0xff00, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000};

u16 gOptionsGeneralPanelEntries[120] = {
    0x035e, 0x0017, 0x005a, 0x00cb, 0x0000, 0x005a, 0x0116, 0x0000, 0xffff, 0xffff, 0x0000, 0x0021, 0x0000, 0xff01, 0xffff, 0xff00,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0360, 0x0018,
    0x005a, 0x0119, 0x0000, 0x005a, 0x0146, 0x0000, 0xffff, 0xffff, 0x0000, 0x0021, 0x0000, 0x0002, 0xffff, 0xff00, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0500, 0x0019, 0x005a, 0x0119,
    0x0000, 0x005a, 0x0146, 0x0000, 0xffff, 0xffff, 0x0000, 0x0021, 0x0000, 0x0103, 0xffff, 0xff00, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0502, 0x001a, 0x005a, 0x0119, 0x0000, 0x005a,
    0x0146, 0x0000, 0xffff, 0xffff, 0x0000, 0x0021, 0x0000, 0x02ff, 0xffff, 0xff00, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000};

u16 gOptionsAudioPanelEntries[180] = {
    0x0361, 0x0017, 0x005a, 0x00b1, 0x0000, 0x005a, 0x00fe, 0x0000, 0xffff, 0xffff, 0x0000, 0x0021, 0x0000, 0xff01, 0xffff, 0xff00,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0362, 0x0018,
    0x005a, 0x00e5, 0x0000, 0x005a, 0x0116, 0x0000, 0xffff, 0xffff, 0x0000, 0x0021, 0x0000, 0x0002, 0xffff, 0xff00, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0363, 0x0019, 0x005a, 0x00ff,
    0x0000, 0x005a, 0x012e, 0x0000, 0xffff, 0xffff, 0x0000, 0x0021, 0x0000, 0x0103, 0xffff, 0xff00, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x03a8, 0x001a, 0x005a, 0x00ff, 0x0000, 0x005a,
    0x012e, 0x0000, 0xffff, 0xffff, 0x0000, 0x0021, 0x0000, 0x0204, 0xffff, 0xff00, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0364, 0x001b, 0x005a, 0x00ff, 0x0000, 0x005a, 0x012e, 0x0000,
    0xffff, 0xffff, 0x0000, 0x0001, 0x0000, 0x0305, 0xffff, 0xff00, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x03ca, 0x001c, 0x005a, 0x00ff, 0x0000, 0x005a, 0x012e, 0x0000, 0xffff, 0xffff,
    0x0000, 0x0001, 0x0000, 0x04ff, 0xffff, 0xff00, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000};

u16 gOptionsMiscPanelEntries[90] = {
    0x035f, 0x0017, 0x0140, 0x0170, 0x0000, 0x0140, 0x00bb, 0x0000, 0xffff, 0xffff, 0x00b4, 0x0000, 0x0000, 0xff01, 0xffff, 0xff00,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0506, 0x0018,
    0x0140, 0x0170, 0x0000, 0x0140, 0x00bb, 0x0000, 0xffff, 0xffff, 0x00b4, 0x0000, 0x0000, 0x00ff, 0xffff, 0xff00, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0369, 0x0002, 0x0109, 0x0188,
    0x0000, 0x0109, 0x017c, 0x0000, 0xffff, 0xffff, 0x0000, 0x0000, 0x0000, 0xffff, 0xffff, 0xff00, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000};

OptionsScreenPanelConfig gOptionsPanelTable[4] = {
    {gOptionsTopPanelEntries, 0, 0x0304, 0x0330, 0x0367, 0},
    {gOptionsAudioPanelEntries, 0, 0x0603, 0x035c, 0x0368, 0},
    {gOptionsGeneralPanelEntries, 0, 0x0403, 0x035a, 0x0368, 0},
    {gOptionsMiscPanelEntries, 0, 0x0203, 0x035b, 0x0368, 0},
};

ObjectDescriptor6 OptionsScreen_funcs = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_6_SLOTS,
    (ObjectDescriptorCallback)OptionsScreen_initialise,
    (ObjectDescriptorCallback)OptionsScreen_release,
    0,
    (ObjectDescriptorCallback)OptionsScreen_frameStart,
    (ObjectDescriptorCallback)OptionsScreen_frameEnd,
    (ObjectDescriptorCallback)OptionsScreen_render,
};


void OptionsScreen_render(int arg)
{
    int alpha;
    int fade;
    TitleMenuItem** item;
    int i;
    OptionsScreenPanelConfig* panel = &gOptionsPanelTable[gOptionsActivePanel];

    if (shouldShowCredits() != 0)
    {
        creditsStart_();
        return;
    }

    alpha = (int)(255.0f - (*gScreenTransitionInterface)->getProgress());
    gameTextSetDrawFunc(titleScreenTextDrawFunc);

    if ((u8)alpha < 0x80)
    {
        f32 conv = (f32)((u8)alpha * 0x86);
        titleScreenPositionElements(40.0f, 254.0f - conv / 128.0f);
        fade = 0;
    }
    else
    {
        titleScreenPositionElements(40.0f, 120.0f);
        fade = ((int)((u8)alpha & 0x7f) << 1) & 0xff;
    }

    titleScreenDrawMenuFrame(fade, 0, 0);
    if (panel->selectionTextId != 0xffff)
    {
        gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        *(u8*)((char*)gameTextGetBox(*(u8*)((char*)gameTextGet(panel->selectionTextId) + 4)) + 0x1e) = fade;
        gameTextShow(panel->selectionTextId);
    }
    if (panel->headingTextId != 0xffff)
    {
        gameTextSetColor(0xff, 0xff, 0xff, fade);
        gameTextShow(panel->headingTextId);
    }

    item = gOptionsMenuItems;
    for (i = 0; i < OPTIONSSCREEN_MENU_ITEM_COUNT; i++)
    {
        if (item[i] != NULL)
        {
            gTitleMenuItemInterface->vtable->render(item[i], arg, fade);
        }
    }
    gTitleMenuLinkInterface->vtable->setOpacity(fade);
    gTitleMenuLinkInterface->vtable->render(arg);
    gameTextSetDrawFunc(0);
    titleScreenShowCopyright(0);
    if ((s8)--gOptionsLayoutRefreshFrames < 0)
    {
        gOptionsLayoutRefreshFrames = 0;
    }
}

void OptionsScreen_frameEnd(void)
{
}

static inline void optionsScreenFreeMenuItems(void)
{
    int i;

    for (i = 0; i < OPTIONSSCREEN_MENU_ITEM_COUNT; i++)
    {
        if (gOptionsMenuItems[i] != NULL)
        {
            gTitleMenuItemInterface->vtable->free(gOptionsMenuItems[i]);
            gOptionsMenuItems[i] = NULL;
        }
    }
}

int OptionsScreen_frameStart(void)
{
    int step = framesThisStep;
    s8 oldFade = gOptionsExitCountdown;
    int selection;
    int item;
    int i;

    if (shouldShowCredits())
    {
        return 0;
    }
    if (step > 3)
    {
        step = 3;
    }
    if (gOptionsExitCountdown > 0)
    {
        gOptionsExitCountdown = (s8)(gOptionsExitCountdown - step);
    }
    if ((*gScreenTransitionInterface)->isFinished() == 0)
    {
        gTitleMenuLinkInterface->vtable->resetTimers();
        gOptionsLayoutRefreshFrames = 2;
    }

    if (gOptionsExitRequested != 0)
    {
        if ((oldFade <= 0xc || gOptionsExitCountdown > 0xc) && gOptionsExitCountdown <= 0)
        {
            if (gOptionsActivePanel != OPTIONSSCREEN_PANEL_NONE)
            {
                gTitleMenuLinkInterface->vtable->free();
                gOptionsActivePanel = OPTIONSSCREEN_PANEL_NONE;
            }
            optionsScreenFreeMenuItems();
            setTitleScreenActive(1);
            setDrawCloudsAndLights(1);
            loadUiDll(4);
        }
        return gOptionsExitCountdown <= 12;
    }

    selection = gTitleMenuLinkInterface->vtable->update();
    item = gTitleMenuLinkInterface->vtable->getSelected();
    if (item != gOptionsLastSelectedRow)
    {
        Sfx_PlayFromObject(0, SFXTRIG_warningloop);
    }
    gOptionsLastSelectedRow = item;

    switch (gOptionsActivePanel)
    {
    case OPTIONSSCREEN_PANEL_TOP:
        lbl_803DD70C = item;
        if (optionsMenu_openSelectedSubmenu(selection, item) != 0)
        {
            return 0;
        }
        break;
    case OPTIONSSCREEN_PANEL_GAMEPLAY:
        optionsMenu_applyGameplaySetting(selection, item);
        if (selection == 0)
        {
            gOptionsSaveData->widescreenEnabled = gTitleMenuItemInterface->vtable->getValue(gOptionsMenuItems[0]);
            gOptionsSaveData->rumbleEnabled = !gTitleMenuItemInterface->vtable->getValue(gOptionsMenuItems[1]);
            setWidescreen(gOptionsSaveData->widescreenEnabled);
            setRumbleEnabled(gOptionsSaveData->rumbleEnabled);
        }
        break;
    case OPTIONSSCREEN_PANEL_AUDIO:
        optionsMenu_applyAudioSetting(selection, item);
        if (selection == 0)
        {
            gOptionsSaveData->soundMode = gTitleMenuItemInterface->vtable->getValue(gOptionsMenuItems[0]);
            gOptionsSaveData->musicVolume = gTitleMenuItemInterface->vtable->getValue(gOptionsMenuItems[1]);
            gOptionsSaveData->sfxVolume = gTitleMenuItemInterface->vtable->getValue(gOptionsMenuItems[2]);
            gOptionsSaveData->speechVolume = gTitleMenuItemInterface->vtable->getValue(gOptionsMenuItems[3]);
        }
        break;
    case OPTIONSSCREEN_PANEL_MISC:
        if (selection == 0)
        {
            Sfx_PlayFromObject(0, SFXTRIG_wmap_name);
            (*gScreenTransitionInterface)->start(0x14, SCREEN_TRANSITION_HUD);
            gOptionsExitCountdown = 0x23;
            gOptionsExitRequested = 1;
        }
        if (gOptionsMenuItems[item] != NULL && gTitleMenuItemInterface->vtable->isChanged(gOptionsMenuItems[item]) != 0)
        {
            switch (item)
            {
            case 0:
                gOptionsSaveData->subtitlesEnabled = !gTitleMenuItemInterface->vtable->getValue(gOptionsMenuItems[0]);
                setSubtitlesEnabled(gOptionsSaveData->subtitlesEnabled);
                break;
            default:
                saveFileStruct_setCheatActive(CHEAT_DINO_LANGUAGE,
                                              !gTitleMenuItemInterface->vtable->getValue(gOptionsMenuItems[item]));
                break;
            }
        }
        break;
    }

    if (gOptionsActivePanel != OPTIONSSCREEN_PANEL_TOP)
    {
        for (i = 0; i < OPTIONSSCREEN_MENU_ITEM_COUNT; i++)
        {
            if (gOptionsMenuItems[i] != NULL)
            {
                if (i == item)
                {
                    gTitleMenuItemInterface->vtable->setEnabled(gOptionsMenuItems[i], 1);
                }
                else
                {
                    gTitleMenuItemInterface->vtable->setEnabled(gOptionsMenuItems[i], 0);
                }
                gTitleMenuItemInterface->vtable->update(gOptionsMenuItems[i]);
            }
        }
    }
    return 0;
}

void OptionsScreen_release(void)
{
}

void OptionsScreen_initialise(void)
{
    (*gScreenTransitionInterface)->step(20, SCREEN_TRANSITION_HUD);
    gameTextLoadDir(21);
    lbl_803DD70C = 0;
    gOptionsSaveData = getSaveFileStruct();
    if (gOptionsRequestedPanel == 0)
    {
        optionsMenu_openGeneralPanel();
    }
    else if (gOptionsRequestedPanel == 1)
    {
        optionsMenu_openAudioPanel();
    }
    else
    {
        languageMenuInit();
    }
    gOptionsLayoutRefreshFrames = 2;
    gOptionsExitRequested = 0;
    lbl_803DD6F9 = 0;
}
