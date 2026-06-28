/*
 * optionsscreen (DLL 0x37) - the front-end Options screen, run as a
 * title-menu sub-state through gTitleMenuLinkInterface / gTitleMenuItemInterface.
 *
 * lbl_803DBA28 selects the active panel: 0 = top-level options list,
 * 1 = audio, 2 = gameplay (widescreen / rumble), 3 = misc (subtitles +
 * cheat toggles). _run() reads the highlighted item, dispatches to the
 * matching optionsMenu_* handler, and mirrors the chosen settings into
 * the save-file struct (lbl_803DD708) byte fields: [2]=subtitles,
 * [6]=widescreen, [8]=rumble, [9..12]=audio. _render() fades the panel
 * text in/out against the screen-transition progress; _initialise()
 * loads the text directory and the active panel's item list. Selecting
 * Exit (panel 3, item 0) starts the transition out and reloads UI DLL 4.
 */
#include "main/audio/sfx_ids.h"
#include "main/dll/dll_4E.h"
#include "main/screen_transition.h"
#include "main/dll/gameplay.h"
#include "main/dll/dll_4D.h"
#include "main/engine_shared.h"
extern void saveFileStruct_setCheatActive(u32 cheatId, u8 enabled);
extern int* gTitleMenuItemInterface;
extern int* gTitleMenuLinkInterface;
extern s8 lbl_803DBA28;        /* active panel id (-1 = none) */
extern u16 lbl_8031ACB8[];     /* per-panel text-box table, 8 u16 per panel */
extern int lbl_803A87D0[8];    /* the 8 menu-item objects of the active panel */
/* Menu-item slots per options panel (lbl_803A87D0[8], size 0x20 / 4). */
#define OPTIONSSCREEN_MENU_ITEM_COUNT 8
extern f32 lbl_803E1DD4;
extern f32 lbl_803E1DD8;
extern f32 lbl_803E1DDC;
extern f32 lbl_803E1DE0;
extern f32 lbl_803E1DE4;
extern u8 shouldShowCredits(void);
extern void titleScreenTextDrawFunc(void);
extern void titleScreenPositionElements(f32 a, f32 b);
extern void gameTextBoxFn_80134d40(int p1, int p2, u32 p3);
extern void titleScreenShowCopyright(u8 arg);
extern void gameTextLoadDir(int dirId);
extern s8 lbl_803DD706;        /* render-stale countdown */
extern s8 lbl_803DD70C;        /* last top-level item index (read by other DLL) */
extern u8* lbl_803DD708;       /* save-file struct base */
extern s8 lbl_803DD705;        /* exit-in-progress flag */
extern u8 lbl_803DD6F9;
extern u8 lbl_803DD6F8;        /* initial panel selector */
extern void fn_8011CA74(void);
extern void fn_8011C7B4(void);
extern s8 lbl_803DD704;        /* exit fade countdown */
extern int lbl_803DD700;       /* last highlighted item (for select sfx) */
extern void setDrawCloudsAndLights(int v);
extern void setWidescreen(u8 enabled);
extern void setSubtitlesEnabled(u8 enabled);

#pragma scheduling off
#pragma peephole off
void OptionsScreen_render(int arg)
{
    int alpha;
    int fade;
    int* item;
    int i;
    u16* panel = &lbl_8031ACB8[lbl_803DBA28 * 8];

    if (shouldShowCredits() != 0)
    {
        creditsStart_();
        return;
    }

    alpha = (int)(lbl_803E1DD4 - (*gScreenTransitionInterface)->getProgress());
    gameTextSetDrawFunc(titleScreenTextDrawFunc);

    if ((u8)alpha < 0x80)
    {
        f32 conv = (f32)((u8)alpha * 0x86);
        titleScreenPositionElements(lbl_803E1DD8,
                                    -(conv * lbl_803E1DE0 - lbl_803E1DDC));
        fade = 0;
    }
    else
    {
        titleScreenPositionElements(lbl_803E1DD8, lbl_803E1DE4);
        fade = (((u8)alpha & 0x7f) << 1);
    }

    gameTextBoxFn_80134d40(fade, 0, 0);
    if (panel[5] != 0xffff)
    {
        gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        *(u8*)((char*)gameTextGetBox(*(u8*)((char*)gameTextGet(panel[5]) + 4)) + 0x1e) = fade;
        gameTextShow(panel[5]);
    }
    if (panel[6] != 0xffff)
    {
        gameTextSetColor(0xff, 0xff, 0xff, fade);
        gameTextShow(panel[6]);
    }

    item = lbl_803A87D0;
    for (i = 0; i < OPTIONSSCREEN_MENU_ITEM_COUNT; i++)
    {
        if (*(void**)&item[i] != NULL)
        {
            (*(void (*)(int, int, int))(*(int*)(*gTitleMenuItemInterface + 0x18)))(item[i], arg, fade);
        }
    }
    (*(void (*)(int))(*(int*)(*gTitleMenuLinkInterface + 0x30)))(fade);
    (*(void (*)(int))(*(int*)(*gTitleMenuLinkInterface + 0x10)))(arg);
    gameTextSetDrawFunc(0);
    titleScreenShowCopyright(0);
    if ((s8)--lbl_803DD706 < 0)
    {
        lbl_803DD706 = 0;
    }
}

#pragma peephole on
void OptionsScreen_initialise(void)
{
    (*gScreenTransitionInterface)->step(20, 5);
    gameTextLoadDir(21);
    lbl_803DD70C = 0;
    lbl_803DD708 = getSaveFileStruct();
    if (lbl_803DD6F8 == 0)
    {
        fn_8011CA74();
    }
    else if (lbl_803DD6F8 == 1)
    {
        fn_8011C7B4();
    }
    else
    {
        languageMenuInit();
    }
    lbl_803DD706 = 2;
    lbl_803DD705 = 0;
    lbl_803DD6F9 = 0;
}

#pragma peephole off
int OptionsScreen_run(void)
{
    int step = framesThisStep;
    s8 oldFade = lbl_803DD704;
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
    if (lbl_803DD704 > 0)
    {
        lbl_803DD704 = (s8)(lbl_803DD704 - step);
    }
    if ((*gScreenTransitionInterface)->isFinished() == 0)
    {
        (*(void (*)(void))(*(int*)(*gTitleMenuLinkInterface + 0x34)))();
        lbl_803DD706 = 2;
    }

    if (lbl_803DD705 != 0)
    {
        if ((oldFade <= 0xc || lbl_803DD704 > 0xc) && lbl_803DD704 <= 0)
        {
            if ((s8)lbl_803DBA28 != -1)
            {
                (*(void (*)(void))(*(int*)(*gTitleMenuLinkInterface + 0x8)))();
                lbl_803DBA28 = -1;
            }
            for (i = 0; i < OPTIONSSCREEN_MENU_ITEM_COUNT; i++)
            {
                if ((u32)lbl_803A87D0[i] != 0)
                {
                    (*(void (*)(int))(*(int*)(*gTitleMenuItemInterface + 0x10)))(lbl_803A87D0[i]);
                    lbl_803A87D0[i] = 0;
                }
            }
            titleScreenFn_8005cdd4(1);
            setDrawCloudsAndLights(1);
            loadUiDll(4);
        }
        return lbl_803DD704 <= 12;
    }

    selection = (*(int (*)(void))(*(int*)(*gTitleMenuLinkInterface + 0xc)))();
    item = (*(int (*)(void))(*(int*)(*gTitleMenuLinkInterface + 0x14)))();
    if (item != lbl_803DD700)
    {
        Sfx_PlayFromObject(0, SFXsp_sa_off03);
    }
    lbl_803DD700 = item;

    switch ((s8)lbl_803DBA28)
    {
    case 0:
        lbl_803DD70C = item;
        if (optionsMenu_openSelectedSubmenu(selection, item) != 0)
        {
            return 0;
        }
        break;
    case 2:
        optionsMenu_applyGameplaySetting(selection, item);
        if (selection == 0)
        {
            lbl_803DD708[6] =
                (*(int (*)(int))(*(int*)(*gTitleMenuItemInterface + 0x24)))(lbl_803A87D0[0]);
            lbl_803DD708[8] =
                !(*(int (*)(int))(*(int*)(*gTitleMenuItemInterface + 0x24)))(lbl_803A87D0[1]);
            setWidescreen(lbl_803DD708[6]);
            setRumbleEnabled(lbl_803DD708[8]);
        }
        break;
    case 1:
        optionsMenu_applyAudioSetting(selection, item);
        if (selection == 0)
        {
            lbl_803DD708[9] =
                (*(int (*)(int))(*(int*)(*gTitleMenuItemInterface + 0x24)))(lbl_803A87D0[0]);
            lbl_803DD708[10] =
                (*(int (*)(int))(*(int*)(*gTitleMenuItemInterface + 0x24)))(lbl_803A87D0[1]);
            lbl_803DD708[11] =
                (*(int (*)(int))(*(int*)(*gTitleMenuItemInterface + 0x24)))(lbl_803A87D0[2]);
            lbl_803DD708[12] =
                (*(int (*)(int))(*(int*)(*gTitleMenuItemInterface + 0x24)))(lbl_803A87D0[3]);
        }
        break;
    case 3:
        if (selection == 0)
        {
            Sfx_PlayFromObject(0, SFXsp_snrot1_c);
            (*gScreenTransitionInterface)->start(0x14, 5);
            lbl_803DD704 = 0x23;
            lbl_803DD705 = 1;
        }
        if ((u32)lbl_803A87D0[item] != 0 &&
            (*(int (*)(int))(*(int*)(*gTitleMenuItemInterface + 0x2c)))(lbl_803A87D0[item]) != 0)
        {
            switch (item)
            {
            case 0:
                lbl_803DD708[2] =
                    !(*(int (*)(int))(*(int*)(*gTitleMenuItemInterface + 0x24)))(lbl_803A87D0[0]);
                setSubtitlesEnabled(lbl_803DD708[2]);
                break;
            default:
                saveFileStruct_setCheatActive(3,
                                              !(*(int (*)(int))(*(int*)(*gTitleMenuItemInterface + 0x24)))(
                                                  lbl_803A87D0[item]));
                break;
            }
        }
        break;
    }

    if ((s8)lbl_803DBA28 != 0)
    {
        for (i = 0; i < OPTIONSSCREEN_MENU_ITEM_COUNT; i++)
        {
            if ((u32)lbl_803A87D0[i] != 0)
            {
                if (i == item)
                {
                    (*(void (*)(int, int))(*(int*)(*gTitleMenuItemInterface + 0x20)))(lbl_803A87D0[i], 1);
                }
                else
                {
                    (*(void (*)(int, int))(*(int*)(*gTitleMenuItemInterface + 0x20)))(lbl_803A87D0[i], 0);
                }
                (*(void (*)(int))(*(int*)(*gTitleMenuItemInterface + 0x14)))(lbl_803A87D0[i]);
            }
        }
    }
    return 0;
}

#pragma scheduling on
#pragma peephole on
void OptionsScreen_frameEnd(void)
{
}

void OptionsScreen_release(void)
{
}
