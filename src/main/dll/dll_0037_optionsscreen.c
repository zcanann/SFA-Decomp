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
#include "main/model_engine.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/sfx.h"
#include "main/dll/dll_4E.h"
#include "main/dll/dll_02C0_front_api.h"
#include "main/frame_timing.h"
#include "main/gametext_box_api.h"
#include "main/gametext_show_api.h"
#include "main/lightmap_api.h"
#include "main/lightmap_render_control_api.h"
#include "main/pad.h"
#include "main/screen_transition.h"
#include "main/textrender_api.h"
#include "main/dll/dll_0015_save_settings.h"
#include "main/dll/dll_4D.h"
#include "main/dll/FRONT/title_menu.h"
#include "main/dll/savedata_struct.h"
#include "main/dll/debug/prof.h"
#include "main/dll/dll_0037_optionsscreen.h"

/* Menu-item slots per options panel (lbl_803A87D0[8], size 0x20 / 4). */
#define OPTIONSSCREEN_MENU_ITEM_COUNT 8

/* Active panel id (lbl_803DBA28; see file header). */
#define OPTIONSSCREEN_PANEL_NONE     (-1)
#define OPTIONSSCREEN_PANEL_TOP      0
#define OPTIONSSCREEN_PANEL_AUDIO    1
#define OPTIONSSCREEN_PANEL_GAMEPLAY 2
#define OPTIONSSCREEN_PANEL_MISC     3

extern TitleMenuControl* gTitleMenuItemInterface;
extern TitleMenuControl* gTitleMenuLinkInterface;
s8 lbl_803DBA28 = -1;      /* active panel id (-1 = none) */
extern int lbl_803A87D0[8]; /* the 8 menu-item objects of the active panel */
extern f32 lbl_803E1DD4;
extern f32 lbl_803E1DD8;
extern f32 lbl_803E1DDC;
extern f32 lbl_803E1DE0;
extern f32 lbl_803E1DE4;
extern s8 lbl_803DD706;  /* render-stale countdown */
extern s8 lbl_803DD70C;  /* last top-level item index (read by other DLL) */
extern u8* lbl_803DD708; /* save-file struct base */
extern s8 lbl_803DD705;  /* exit-in-progress flag */
extern u8 lbl_803DD6F9;
extern u8 lbl_803DD6F8;  /* initial panel selector */
extern s8 lbl_803DD704;  /* exit fade countdown */
extern int lbl_803DD700; /* last highlighted item (for select sfx) */
extern void saveFileStruct_setCheatActive(u32 cheatId, u8 enabled);
extern u8 shouldShowCredits(void);
extern void gameTextBoxFn_80134d40(int p1, int p2, u32 p3);

u16 lbl_8031A8F8[90] = {
    0x035a, 0x0012, 0x0140, 0x00a4, 0x0000, 0x0140, 0x0034, 0x0000, 0xffff, 0xffff, 0x00c8, 0x0200, 0x0000, 0xff01, 0xffff, 0xff00,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x035c, 0x0013,
    0x0140, 0x0110, 0x0000, 0x0140, 0x00a0, 0x0000, 0xffff, 0xffff, 0x00c8, 0x0200, 0x0000, 0x01ff, 0xffff, 0xff00, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x035b, 0x0014, 0x0140, 0x00da,
    0x0000, 0x0140, 0x006a, 0x0000, 0xffff, 0xffff, 0x00c8, 0x0200, 0x0000, 0x0002, 0xffff, 0xff00, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000};

u16 lbl_8031A9AC[120] = {
    0x035e, 0x0017, 0x005a, 0x00cb, 0x0000, 0x005a, 0x0116, 0x0000, 0xffff, 0xffff, 0x0000, 0x0021, 0x0000, 0xff01, 0xffff, 0xff00,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0360, 0x0018,
    0x005a, 0x0119, 0x0000, 0x005a, 0x0146, 0x0000, 0xffff, 0xffff, 0x0000, 0x0021, 0x0000, 0x0002, 0xffff, 0xff00, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0500, 0x0019, 0x005a, 0x0119,
    0x0000, 0x005a, 0x0146, 0x0000, 0xffff, 0xffff, 0x0000, 0x0021, 0x0000, 0x0103, 0xffff, 0xff00, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0502, 0x001a, 0x005a, 0x0119, 0x0000, 0x005a,
    0x0146, 0x0000, 0xffff, 0xffff, 0x0000, 0x0021, 0x0000, 0x02ff, 0xffff, 0xff00, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000};

u16 lbl_8031AA9C[180] = {
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

u16 lbl_8031AC04[90] = {
    0x035f, 0x0017, 0x0140, 0x0170, 0x0000, 0x0140, 0x00bb, 0x0000, 0xffff, 0xffff, 0x00b4, 0x0000, 0x0000, 0xff01, 0xffff, 0xff00,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0506, 0x0018,
    0x0140, 0x0170, 0x0000, 0x0140, 0x00bb, 0x0000, 0xffff, 0xffff, 0x00b4, 0x0000, 0x0000, 0x00ff, 0xffff, 0xff00, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0369, 0x0002, 0x0109, 0x0188,
    0x0000, 0x0109, 0x017c, 0x0000, 0xffff, 0xffff, 0x0000, 0x0000, 0x0000, 0xffff, 0xffff, 0xff00, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000};

u32 lbl_8031ACB8[16] = {(u32)lbl_8031A8F8, 0x00000000, 0x03040330, 0x03670000,
        (u32)lbl_8031AA9C, 0x00000000, 0x0603035c, 0x03680000,
        (u32)lbl_8031A9AC, 0x00000000, 0x0403035a, 0x03680000,
        (u32)lbl_8031AC04, 0x00000000, 0x0203035b, 0x03680000};

u32 lbl_8031ACF8[10] = {0x00000000, 0x00000000, 0x00000000, 0x00050000,
        (u32)OptionsScreen_initialise, (u32)OptionsScreen_release,
        0x00000000, (u32)OptionsScreen_frameStart, (u32)OptionsScreen_frameEnd,
        (u32)OptionsScreen_render};

#pragma scheduling off
#pragma peephole off
void OptionsScreen_render(int arg)
{
    int alpha;
    int fade;
    int* item;
    int i;
    u16* panel = (u16*)lbl_8031ACB8 + lbl_803DBA28 * 8;

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
        titleScreenPositionElements(lbl_803E1DD8, -(conv * lbl_803E1DE0 - lbl_803E1DDC));
        fade = 0;
    }
    else
    {
        titleScreenPositionElements(lbl_803E1DD8, lbl_803E1DE4);
        fade = ((int)((u8)alpha & 0x7f) << 1) & 0xff;
    }

    gameTextBoxFn_80134d40(fade, 0, 0);
    if (panel[5] != 0xffff)
    {
        gameTextSetColorInt(0xff, 0xff, 0xff, 0xff);
        *(u8*)((char*)gameTextGetBox(*(u8*)((char*)gameTextGet(panel[5]) + 4)) + 0x1e) = fade;
        gameTextShow(panel[5]);
    }
    if (panel[6] != 0xffff)
    {
        gameTextSetColorInt(0xff, 0xff, 0xff, fade);
        gameTextShow(panel[6]);
    }

    item = lbl_803A87D0;
    for (i = 0; i < OPTIONSSCREEN_MENU_ITEM_COUNT; i++)
    {
        if (*(void**)&item[i] != NULL)
        {
            ((void (**)(int, int, int))gTitleMenuItemInterface->vtable)[6](item[i], arg, fade);
        }
    }
    ((void (**)(int))gTitleMenuLinkInterface->vtable)[12](fade);
    ((void (**)(int))gTitleMenuLinkInterface->vtable)[4](arg);
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
        optionsMenu_openGeneralPanel();
    }
    else if (lbl_803DD6F8 == 1)
    {
        optionsMenu_openAudioPanel();
    }
    else
    {
        languageMenuInit();
    }
    lbl_803DD706 = 2;
    lbl_803DD705 = 0;
    lbl_803DD6F9 = 0;
}

static inline void optionsScreenFreeMenuItems(void)
{
    int i;

    for (i = 0; i < OPTIONSSCREEN_MENU_ITEM_COUNT; i++)
    {
        if ((u32)lbl_803A87D0[i] != 0)
        {
            ((void (**)(int))gTitleMenuItemInterface->vtable)[4](lbl_803A87D0[i]);
            lbl_803A87D0[i] = 0;
        }
    }
}

#pragma peephole off
int OptionsScreen_frameStart(void)
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
        ((void (**)(void))gTitleMenuLinkInterface->vtable)[13]();
        lbl_803DD706 = 2;
    }

    if (lbl_803DD705 != 0)
    {
        if ((oldFade <= 0xc || lbl_803DD704 > 0xc) && lbl_803DD704 <= 0)
        {
            if ((s8)lbl_803DBA28 != OPTIONSSCREEN_PANEL_NONE)
            {
                ((void (**)(void))gTitleMenuLinkInterface->vtable)[2]();
                lbl_803DBA28 = OPTIONSSCREEN_PANEL_NONE;
            }
            optionsScreenFreeMenuItems();
            titleScreenFn_8005cdd4(1);
            setDrawCloudsAndLights(1);
            loadUiDll(4);
        }
        return lbl_803DD704 <= 12;
    }

    selection = ((int (**)(void))gTitleMenuLinkInterface->vtable)[3]();
    item = ((int (**)(void))gTitleMenuLinkInterface->vtable)[5]();
    if (item != lbl_803DD700)
    {
        Sfx_PlayFromObject(0, SFXTRIG_warningloop);
    }
    lbl_803DD700 = item;

    switch ((s8)lbl_803DBA28)
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
            lbl_803DD708[6] = ((int (**)(int))gTitleMenuItemInterface->vtable)[9](lbl_803A87D0[0]);
            lbl_803DD708[8] = !((int (**)(int))gTitleMenuItemInterface->vtable)[9](lbl_803A87D0[1]);
            setWidescreen(lbl_803DD708[6]);
            setRumbleEnabled(lbl_803DD708[8]);
        }
        break;
    case OPTIONSSCREEN_PANEL_AUDIO:
        optionsMenu_applyAudioSetting(selection, item);
        if (selection == 0)
        {
            lbl_803DD708[9] = ((int (**)(int))gTitleMenuItemInterface->vtable)[9](lbl_803A87D0[0]);
            lbl_803DD708[10] = ((int (**)(int))gTitleMenuItemInterface->vtable)[9](lbl_803A87D0[1]);
            lbl_803DD708[11] = ((int (**)(int))gTitleMenuItemInterface->vtable)[9](lbl_803A87D0[2]);
            lbl_803DD708[12] = ((int (**)(int))gTitleMenuItemInterface->vtable)[9](lbl_803A87D0[3]);
        }
        break;
    case OPTIONSSCREEN_PANEL_MISC:
        if (selection == 0)
        {
            Sfx_PlayFromObject(0, SFXTRIG_wmap_name);
            (*gScreenTransitionInterface)->start(0x14, 5);
            lbl_803DD704 = 0x23;
            lbl_803DD705 = 1;
        }
        if ((u32)lbl_803A87D0[item] != 0 &&
            ((int (**)(int))gTitleMenuItemInterface->vtable)[11](lbl_803A87D0[item]) != 0)
        {
            switch (item)
            {
            case 0:
                lbl_803DD708[2] = !((int (**)(int))gTitleMenuItemInterface->vtable)[9](lbl_803A87D0[0]);
                setSubtitlesEnabled(lbl_803DD708[2]);
                break;
            default:
                saveFileStruct_setCheatActive(CHEAT_DINO_LANGUAGE,
                                              !((int (**)(int))gTitleMenuItemInterface->vtable)[9](lbl_803A87D0[item]));
                break;
            }
        }
        break;
    }

    if ((s8)lbl_803DBA28 != OPTIONSSCREEN_PANEL_TOP)
    {
        for (i = 0; i < OPTIONSSCREEN_MENU_ITEM_COUNT; i++)
        {
            if ((u32)lbl_803A87D0[i] != 0)
            {
                if (i == item)
                {
                    ((void (**)(int, int))gTitleMenuItemInterface->vtable)[8](lbl_803A87D0[i], 1);
                }
                else
                {
                    ((void (**)(int, int))gTitleMenuItemInterface->vtable)[8](lbl_803A87D0[i], 0);
                }
                ((void (**)(int))gTitleMenuItemInterface->vtable)[5](lbl_803A87D0[i]);
            }
        }
    }
    return 0;
}

void OptionsScreen_frameEnd(void)
{
}

void OptionsScreen_release(void)
{
}
