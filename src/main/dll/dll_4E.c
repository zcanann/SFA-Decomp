#include "main/audio/sfx_ids.h"
#include "main/dll/dll_4E.h"
#include "main/screen_transition.h"

#define OPTIONS_MENU_ACTION_CLOSE 0
#define OPTIONS_MENU_ACTION_SELECT 1
#define OPTIONS_MENU_TRANSITION_FRAMES 0x14
#define OPTIONS_MENU_TRANSITION_MODE 5
#define OPTIONS_MENU_NEXT_STATE 0x23
#define OPTIONS_MENU_VOLUME_STEP 10
#define OPTIONS_MENU_ITEM_COUNT 8

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


extern void audioSetSoundMode(u8 mode, u8 enabled);
extern void audioSetVolumes(u8 volume, int p1, int p2, int p3, int p4);
extern void Sfx_StopFromObject(int obj, int sfxId);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void saveFileStruct_resetVolumes(void);


extern ScreenTransitionInterface** gScreenTransitionInterface;
extern int* gTitleMenuControlInterface;
extern int* gTitleMenuItemInterface;
extern int* lbl_803A87D0[8];
extern int lbl_803DD6FC;
extern u8 lbl_803DD704;
extern u8 lbl_803DD705;
extern u8* lbl_803DD708;

/*
 * --INFO--
 *
 * Function: optionsMenu_applyAudioSetting
 * EN v1.0 Address: 0x8011BFC8
 * EN v1.0 Size: 872b
 * EN v1.1 Address: 0x8011C2AC
 * EN v1.1 Size: 848b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void optionsMenu_applyAudioSetting(int p1, int p2)
{
    int value;

    if (lbl_803A87D0[p2] != NULL &&
        (*(int(**)(int*))(*gTitleMenuItemInterface + 0x2c))(lbl_803A87D0[p2]) != 0)
    {
        switch (p2)
        {
        case AUDIO_OPTION_SOUND_MODE:
            audioSetSoundMode((u8)(*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[p2]), 1);
            break;
        case AUDIO_OPTION_SFX_VOLUME:
            value = (*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[p2]);
            audioSetVolumes((u8)value, OPTIONS_MENU_VOLUME_STEP, 0, 1, 0);
            break;
        case AUDIO_OPTION_MUSIC_VOLUME:
            value = (*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[p2]);
            audioSetVolumes((u8)value, OPTIONS_MENU_VOLUME_STEP, 1, 0, 0);
            value = (*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[p2]);
            (*(void(**)(int))(*gTitleMenuControlInterface + 0x28))(value);
            break;
        case AUDIO_OPTION_VOICE_VOLUME:
            value = (*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[p2]);
            audioSetVolumes((u8)value, OPTIONS_MENU_VOLUME_STEP, 0, 0, 1);
            break;
        case AUDIO_OPTION_EXTRA:
            lbl_803DD6FC = (*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[p2]);
            break;
        }
    }
    if ((lbl_803A87D0[p2] == NULL) ||
        ((p2 != AUDIO_OPTION_SFX_VOLUME) && (p2 != AUDIO_OPTION_MUSIC_VOLUME) &&
            (p2 != AUDIO_OPTION_VOICE_VOLUME)))
    {
        Sfx_StopFromObject(0, 0x3b9);
    }
    if (p1 == OPTIONS_MENU_ACTION_CLOSE)
    {
        Sfx_PlayFromObject(0, SFXsp_snrot1_c);
        (*gScreenTransitionInterface)->start(OPTIONS_MENU_TRANSITION_FRAMES,
                                             OPTIONS_MENU_TRANSITION_MODE);
        lbl_803DD704 = OPTIONS_MENU_NEXT_STATE;
        lbl_803DD705 = 1;
    }
    else if ((p1 == OPTIONS_MENU_ACTION_SELECT) && (p2 == AUDIO_OPTION_RESET_DEFAULTS))
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
        Sfx_PlayFromObject(0, 0x418);
    }
}

extern int optionsMenu_openAudioPanel(void);
extern int optionsMenu_openGeneralPanel(void);
extern int languageMenuInit(void);
extern int* gTitleMenuLinkInterface;
extern f32 lbl_803E1DD0;
extern s8 lbl_803DBA28;
extern void setWidescreen(u8 enabled);
extern void stopRumble2(void);
extern void setRumbleEnabled(u8 value);
extern void doRumble(f32 val);
extern void creditsStart(void);
extern void Rcp_SetColorFilterEnabled(int enabled);

void optionsMenu_applyGameplaySetting(int p1, int p2)
{
    int i;
    u8 newState;

    if (lbl_803A87D0[p2] != NULL &&
        (*(int(**)(int*))(*gTitleMenuItemInterface + 0x2c))(lbl_803A87D0[p2]) != 0)
    {
        switch (p2)
        {
        case GAMEPLAY_OPTION_WIDESCREEN:
            setWidescreen((u8)(*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[p2]));
            break;
        case GAMEPLAY_OPTION_RUMBLE:
            newState = (u8)!(*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[p2]);
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
            if ((*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[p2]) == 0)
            {
                creditsStart();
                if (lbl_803DBA28 != -1)
                {
                    (*(void(**)(void))(*gTitleMenuLinkInterface + 0x8))();
                    lbl_803DBA28 = -1;
                }
                for (i = 0; i < OPTIONS_MENU_ITEM_COUNT; i++)
                {
                    if (lbl_803A87D0[i] != NULL)
                    {
                        (*(void(**)(int*))(*gTitleMenuItemInterface + 0x10))(lbl_803A87D0[i]);
                        lbl_803A87D0[i] = NULL;
                    }
                }
            }
            break;
        case GAMEPLAY_OPTION_COLOR_FILTER:
            Rcp_SetColorFilterEnabled((*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[p2]));
            break;
        }
    }
    if (p1 == OPTIONS_MENU_ACTION_CLOSE)
    {
        Sfx_PlayFromObject(0, SFXsp_snrot1_c);
        (*gScreenTransitionInterface)->start(OPTIONS_MENU_TRANSITION_FRAMES,
                                             OPTIONS_MENU_TRANSITION_MODE);
        lbl_803DD704 = OPTIONS_MENU_NEXT_STATE;
        lbl_803DD705 = 1;
    }
}

int optionsMenu_openSelectedSubmenu(int p1, int p2)
{
    if (p1 == OPTIONS_MENU_ACTION_SELECT)
    {
        switch (p2)
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
    else if (p1 == OPTIONS_MENU_ACTION_CLOSE)
    {
        Sfx_PlayFromObject(0, SFXsp_snrot1_c);
        (*gScreenTransitionInterface)->start(OPTIONS_MENU_TRANSITION_FRAMES,
                                             OPTIONS_MENU_TRANSITION_MODE);
        lbl_803DD704 = OPTIONS_MENU_NEXT_STATE;
        lbl_803DD705 = 1;
    }
    return 0;
}
