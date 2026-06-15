#include "main/audio/sfx_ids.h"
#include "main/dll/dll_4E.h"
#include "main/screen_transition.h"

extern undefined8 FUN_80006b84();
extern undefined4 FUN_80017a98();
extern undefined4 FUN_80053c98();
extern undefined4 saveFileStruct_setCheatActive();
extern u8* getSaveFileStruct();
extern undefined4 languageMenuInit();

extern undefined4 DAT_803dc070;
extern undefined4 DAT_803de3a8;

extern int* gTitleMenuItemInterface;
extern int* gTitleMenuLinkInterface;
extern s8 lbl_803DBA28;
extern u16 lbl_8031ACB8[];
extern int lbl_803A87D0[8];
extern f32 lbl_803E1DD4;
extern f32 lbl_803E1DD8;
extern f32 lbl_803E1DDC;
extern f32 lbl_803E1DE0;
extern f32 lbl_803E1DE4;
extern u8 shouldShowCredits(void);
extern void creditsStart_(void);
extern void titleScreenTextDrawFunc(void);
extern void titleScreenPositionElements(f32 x, f32 y);
extern void gameTextSetDrawFunc(void* fn);
extern void gameTextBoxFn_80134d40(int alpha, int p2, int p3);
extern void gameTextSetColor(int r, int g, int b, int a);
extern u32 gameTextGet(int textId);
extern void* gameTextGetBox(int boxId);
extern void gameTextShow(int textId);
extern void titleScreenShowCopyright(int arg);
extern s8 lbl_803DD706;
#pragma scheduling off
#pragma peephole off
extern void gameTextLoadDir(int);
extern s8 lbl_803DD70C;
extern u32 lbl_803DD708;
extern s8 lbl_803DD705;
extern u8 lbl_803DD6F9;
extern u8 lbl_803DD6F8;
extern void fn_8011CA74(void);
extern void fn_8011C7B4(void);
extern s8 lbl_803DD704;
extern int lbl_803DD700;
extern void loadUiDll(int id);
extern void titleScreenFn_8005cdd4(int v);
extern void setDrawCloudsAndLights(int v);
extern void setWidescreen(u8 enabled);
extern void setRumbleEnabled(u8 enabled);
extern void setSubtitlesEnabled(u8 enabled);
extern u8 framesThisStep;
extern void Sfx_PlayFromObject(int obj, int sfxId);

void OptionsScreen_render(int arg)
{
    int alpha;
    int fade;
    int i;
    int* item;
    u16* panel = &lbl_8031ACB8[(s8)lbl_803DBA28 * 8];

    if (shouldShowCredits() != 0)
    {
        creditsStart_();
        return;
    }

    alpha = (int)(lbl_803E1DD4 - (*gScreenTransitionInterface)->getProgress());
    gameTextSetDrawFunc(titleScreenTextDrawFunc);

    if ((u8)alpha < 0x80)
    {
        titleScreenPositionElements(lbl_803E1DD8,
                                    -((f32)((u8)alpha * 0x86) * lbl_803E1DE0 - lbl_803E1DDC));
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
        *(u8*)((char*)gameTextGetBox(*(u8*)((char*)gameTextGet(panel[5]) + 4)) + 0x1e) = (u8)fade;
        gameTextShow(panel[5]);
    }
    if (panel[6] != 0xffff)
    {
        gameTextSetColor(0xff, 0xff, 0xff, fade);
        gameTextShow(panel[6]);
    }

    item = lbl_803A87D0;
    for (i = 0; i < 8; i++, item++)
    {
        if (*item != 0)
        {
            (*(void (*)(int, int, int))(*(int*)(*gTitleMenuItemInterface + 0x18)))(*item, arg, fade);
        }
    }
    (*(void (*)(int))(*(int*)(*gTitleMenuLinkInterface + 0x30)))(fade);
    (*(void (*)(int))(*(int*)(*gTitleMenuLinkInterface + 0x10)))(arg);
    gameTextSetDrawFunc(0);
    titleScreenShowCopyright(0);
    lbl_803DD706--;
    if ((s8)lbl_803DD706 < 0)
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
    lbl_803DD708 = (u32)getSaveFileStruct();
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
            for (i = 0; i < 8; i++)
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
        lbl_803DD70C = (s8)item;
        if (optionsMenu_openSelectedSubmenu(selection, item) != 0)
        {
            return 0;
        }
        break;
    case 2:
        optionsMenu_applyGameplaySetting(selection, item);
        if (selection == 0)
        {
            ((u8*)lbl_803DD708)[6] =
                (*(int (*)(int))(*(int*)(*gTitleMenuItemInterface + 0x24)))(lbl_803A87D0[0]);
            ((u8*)lbl_803DD708)[8] =
                !(*(int (*)(int))(*(int*)(*gTitleMenuItemInterface + 0x24)))(lbl_803A87D0[1]);
            setWidescreen(((u8*)lbl_803DD708)[6]);
            setRumbleEnabled(((u8*)lbl_803DD708)[8]);
        }
        break;
    case 1:
        optionsMenu_applyAudioSetting(selection, item);
        if (selection == 0)
        {
            ((u8*)lbl_803DD708)[9] =
                (*(int (*)(int))(*(int*)(*gTitleMenuItemInterface + 0x24)))(lbl_803A87D0[0]);
            ((u8*)lbl_803DD708)[10] =
                (*(int (*)(int))(*(int*)(*gTitleMenuItemInterface + 0x24)))(lbl_803A87D0[1]);
            ((u8*)lbl_803DD708)[11] =
                (*(int (*)(int))(*(int*)(*gTitleMenuItemInterface + 0x24)))(lbl_803A87D0[2]);
            ((u8*)lbl_803DD708)[12] =
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
                ((u8*)lbl_803DD708)[2] =
                    !(*(int (*)(int))(*(int*)(*gTitleMenuItemInterface + 0x24)))(lbl_803A87D0[0]);
                setSubtitlesEnabled(((u8*)lbl_803DD708)[2]);
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
        for (i = 0; i < 8; i++)
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
void FUN_8011daf8(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  undefined4 param_9, undefined4 param_10, undefined4 param_11, undefined4 param_12,
                  undefined4 param_13, undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
}

undefined4
FUN_8011dafc(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, undefined4 param_9,
             undefined4 param_10, undefined4 param_11, undefined4 param_12, undefined4 param_13,
             undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    byte bVar1;
    undefined8 uVar2;

    FUN_80017a98();
    bVar1 = DAT_803dc070;
    if (3 < DAT_803dc070)
    {
        bVar1 = 3;
    }
    if (('\0' < DAT_803de3a8) && (DAT_803de3a8 = DAT_803de3a8 - bVar1, DAT_803de3a8 < '\x01'))
    {
        uVar2 = FUN_80006b84(1);
        FUN_80053c98(uVar2, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x60, '\x01', param_11,
                     param_12, param_13, param_14, param_15, param_16);
    }
    return 0;
}

void OptionsScreen_frameEnd(void)
{
}

void OptionsScreen_release(void)
{
}

void WeirdUnusedMenu_render(void);
