/*
 * dll_4e - options-menu setting callbacks (audio panel, gameplay panel,
 * submenu selector).
 *
 * Each callback is driven by the title-menu item widgets in
 * lbl_803A87D0[]: the widget at the option index (the menu row) is
 * queried through the gTitleMenuItemInterface vtable - slot 0x2c tests
 * whether the value changed, slot 0x24 reads the current value, slot
 * 0x28 sets a value, slot 0x10 frees the widget. The action arg selects
 * the menu action (CLOSE vs SELECT); CLOSE plays a back sfx and kicks
 * the screen transition into the next menu state.
 *
 * - applyAudioSetting: sound mode, music/sfx/voice volume, reset to
 *   defaults (reloads the saved volumes from lbl_803DD708[10..12]).
 * - applyGameplaySetting: widescreen, rumble, roll credits, colour
 *   filter.
 * - openSelectedSubmenu: general / audio / language panels.
 */
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/dll/dll_4D.h"
#include "main/dll/dll_4E.h"
#include "main/dll/debug/prof.h"
#include "main/dll/gameplay.h"
#include "main/screen_transition.h"
#include "main/engine_shared.h"

#define OPTIONS_MENU_ACTION_CLOSE 0
#define OPTIONS_MENU_ACTION_SELECT 1
#define OPTIONS_MENU_TRANSITION_FRAMES 0x14
#define OPTIONS_MENU_TRANSITION_MODE 5
#define OPTIONS_MENU_NEXT_STATE 0x23
#define OPTIONS_MENU_VOLUME_STEP 10
#define OPTIONS_MENU_ITEM_COUNT 8

#define OPTIONS_SFX_VOLUME_PREVIEW 0x3b9
#define OPTIONS_SFX_CONFIRM 0x418

#define AUDIO_OPTION_SOUND_MODE 0
#define AUDIO_OPTION_MUSIC_VOLUME 1
#define AUDIO_OPTION_SFX_VOLUME 2
#define AUDIO_OPTION_VOICE_VOLUME 3
#define AUDIO_OPTION_RESET_DEFAULTS 4
#define AUDIO_OPTION_EXTRA 5

#define GAMEPLAY_OPTION_WIDESCREEN 0
#define GAMEPLAY_OPTION_RUMBLE 1
#define GAMEPLAY_OPTION_CREDITS 2
#define GAMEPLAY_OPTION_COLOR_FILTER 3

#define OPTIONS_SUBMENU_GENERAL 0
#define OPTIONS_SUBMENU_AUDIO 2
#define OPTIONS_SUBMENU_LANGUAGE 3

extern int* gTitleMenuControlInterface;
extern int* gTitleMenuItemInterface;
extern int* gTitleMenuLinkInterface;
extern int* lbl_803A87D0[8]; /* the 8 menu-row widgets */
extern int lbl_803DD6FC;
extern s8 lbl_803DD704; /* transition fade counter */
extern s8 lbl_803DD705; /* transition pending flag */
extern u8* lbl_803DD708; /* saved volumes at [10..12] */
extern f32 lbl_803E1DD0; /* rumble strength */
extern s8 lbl_803DBA28;
extern void setWidescreen(u8 enabled);
extern void creditsStart(void);
extern void Rcp_SetColorFilterEnabled(int enabled);

void optionsMenu_applyAudioSetting(int action, int option)
{
    int value;

    if (lbl_803A87D0[option] != NULL &&
        (*(int(**)(int*))(*gTitleMenuItemInterface + 0x2c))(lbl_803A87D0[option]) != 0)
    {
        switch (option)
        {
        case AUDIO_OPTION_SOUND_MODE:
            audioSetSoundMode((u8)(*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[option]), 1);
            break;
        case AUDIO_OPTION_SFX_VOLUME:
            value = (*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[option]);
            audioSetVolumes((u8)value, OPTIONS_MENU_VOLUME_STEP, 0, 1, 0);
            break;
        case AUDIO_OPTION_MUSIC_VOLUME:
            value = (*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[option]);
            audioSetVolumes((u8)value, OPTIONS_MENU_VOLUME_STEP, 1, 0, 0);
            value = (*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[option]);
            (*(void(**)(int))(*gTitleMenuControlInterface + 0x28))(value); /* set music control value */
            break;
        case AUDIO_OPTION_VOICE_VOLUME:
            value = (*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[option]);
            audioSetVolumes((u8)value, OPTIONS_MENU_VOLUME_STEP, 0, 0, 1);
            break;
        case AUDIO_OPTION_EXTRA:
            lbl_803DD6FC = (*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[option]);
            break;
        }
    }
    if ((lbl_803A87D0[option] == NULL) ||
        ((option != AUDIO_OPTION_SFX_VOLUME) && (option != AUDIO_OPTION_MUSIC_VOLUME) &&
            (option != AUDIO_OPTION_VOICE_VOLUME)))
    {
        Sfx_StopFromObject(0, OPTIONS_SFX_VOLUME_PREVIEW);
    }
    if (action == OPTIONS_MENU_ACTION_CLOSE)
    {
        Sfx_PlayFromObject(0, SFXsp_snrot1_c);
        (*gScreenTransitionInterface)->start(OPTIONS_MENU_TRANSITION_FRAMES,
                                             OPTIONS_MENU_TRANSITION_MODE);
        lbl_803DD704 = OPTIONS_MENU_NEXT_STATE;
        lbl_803DD705 = 1;
    }
    else if ((action == OPTIONS_MENU_ACTION_SELECT) && (option == AUDIO_OPTION_RESET_DEFAULTS))
    {
        saveFileStruct_resetVolumes();
        (*(void(**)(int*, u8))(*gTitleMenuItemInterface + 0x28))
            (lbl_803A87D0[AUDIO_OPTION_MUSIC_VOLUME], lbl_803DD708[10]);
        (*(void(**)(int*, u8))(*gTitleMenuItemInterface + 0x28))
            (lbl_803A87D0[AUDIO_OPTION_SFX_VOLUME], lbl_803DD708[11]);
        (*(void(**)(int*, u8))(*gTitleMenuItemInterface + 0x28))
            (lbl_803A87D0[AUDIO_OPTION_VOICE_VOLUME], lbl_803DD708[12]);
        value = (*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))
            (lbl_803A87D0[AUDIO_OPTION_MUSIC_VOLUME]);
        audioSetVolumes((u8)value, OPTIONS_MENU_VOLUME_STEP, 0, 1, 0);
        value = (*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))
            (lbl_803A87D0[AUDIO_OPTION_SFX_VOLUME]);
        audioSetVolumes((u8)value, OPTIONS_MENU_VOLUME_STEP, 1, 0, 0);
        value = (*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))
            (lbl_803A87D0[AUDIO_OPTION_VOICE_VOLUME]);
        audioSetVolumes((u8)value, OPTIONS_MENU_VOLUME_STEP, 0, 0, 1);
        Sfx_PlayFromObject(0, OPTIONS_SFX_CONFIRM);
    }
}

void optionsMenu_applyGameplaySetting(int action, int option)
{
    int z[2];
    u8 newState;

    if (lbl_803A87D0[option] != NULL &&
        (*(int(**)(int*))(*gTitleMenuItemInterface + 0x2c))(lbl_803A87D0[option]) != 0)
    {
        switch (option)
        {
        case GAMEPLAY_OPTION_WIDESCREEN:
            setWidescreen((u8)(*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[option]));
            break;
        case GAMEPLAY_OPTION_RUMBLE:
            newState = !(*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[option]);
            if (newState == 0)
            {
                stopRumble2();
            }
            setRumbleEnabled(newState);
            if (newState != 0)
            {
                doRumble(lbl_803E1DD0);
            }
            break;
        case GAMEPLAY_OPTION_CREDITS:
            if ((*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[option]) == 0)
            {
                creditsStart();
                if (lbl_803DBA28 != -1)
                {
                    (*(void(**)(void))(*gTitleMenuLinkInterface + 0x8))();
                    lbl_803DBA28 = -1;
                }
                z[0] = 0;
                z[1] = z[0];
                for (; z[0] < OPTIONS_MENU_ITEM_COUNT; z[0]++)
                {
                    if (lbl_803A87D0[z[0]] != NULL)
                    {
                        (*(void(**)(int*))(*gTitleMenuItemInterface + 0x10))(lbl_803A87D0[z[0]]);
                        lbl_803A87D0[z[0]] = (int*)z[1];
                    }
                }
            }
            break;
        case GAMEPLAY_OPTION_COLOR_FILTER:
            Rcp_SetColorFilterEnabled((*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[option]));
            break;
        }
    }
    if (action == OPTIONS_MENU_ACTION_CLOSE)
    {
        Sfx_PlayFromObject(0, SFXsp_snrot1_c);
        (*gScreenTransitionInterface)->start(OPTIONS_MENU_TRANSITION_FRAMES,
                                             OPTIONS_MENU_TRANSITION_MODE);
        lbl_803DD704 = OPTIONS_MENU_NEXT_STATE;
        lbl_803DD705 = 1;
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
        Sfx_PlayFromObject(0, SFXsp_snrot1_c);
        (*gScreenTransitionInterface)->start(OPTIONS_MENU_TRANSITION_FRAMES,
                                             OPTIONS_MENU_TRANSITION_MODE);
        lbl_803DD704 = OPTIONS_MENU_NEXT_STATE;
        lbl_803DD705 = 1;
    }
    return 0;
}
