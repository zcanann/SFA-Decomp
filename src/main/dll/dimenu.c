#include "main/audio/sfx_ids.h"
#include "main/dll/dll_4E.h"
#include "main/dll/debug/dimenu.h"
#include "main/screen_transition.h"

typedef struct WeirdMenuWork
{
    u8 pad0[0x16 - 0x0];
    u16 unk16;
    u8 pad18[0x52 - 0x18];
    u16 unk52;
    u8 pad54[0x78 - 0x54];
} WeirdMenuWork;


extern undefined8 FUN_80006b84();
extern undefined4 FUN_80017a98();
extern undefined4 FUN_80053c98();
extern undefined4 saveFileStruct_setCheatActive();
extern u8* getSaveFileStruct();
extern void saveGame_save();
extern undefined4 languageMenuInit();

extern undefined4 DAT_803dc070;
extern undefined4 DAT_803de3a8;

/*
 * --INFO--
 *
 * Function: OptionsScreen_render
 * EN v1.0 Address: 0x8011CD54
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8011CD58
 * EN v1.1 Size: 736b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern ScreenTransitionInterface** gScreenTransitionInterface;
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

/*
 * --INFO--
 *
 * Function: OptionsScreen_run
 * EN v1.0 Address: 0x8011D11C
 * EN v1.0 Size: 1376b
 * EN v1.1 Address: 0x8011D260
 * EN v1.1 Size: 1300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: FUN_8011d67c
 * EN v1.0 Address: 0x8011D67C
 * EN v1.0 Size: 276b
 * EN v1.1 Address: 0x8011D774
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_8011daf8
 * EN v1.0 Address: 0x8011DAF8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8011DA84
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011daf8(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  undefined4 param_9, undefined4 param_10, undefined4 param_11, undefined4 param_12,
                  undefined4 param_13, undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8011dafc
 * EN v1.0 Address: 0x8011DAFC
 * EN v1.0 Size: 292b
 * EN v1.1 Address: 0x8011DB40
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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


/* Trivial 4b 0-arg blr leaves. */
void OptionsScreen_frameEnd(void)
{
}

void OptionsScreen_release(void)
{
}

void WeirdUnusedMenu_render(void)
{
}

void WeirdUnusedMenu_frameEnd(void)
{
}

void Dummy39_render(void)
{
}

void Dummy39_frameEnd(void)
{
}

void Dummy3A_render(void)
{
}

void Dummy3A_frameEnd(void)
{
}

void Dummy3A_release(void)
{
}

void Dummy3A_initialise(void)
{
}

/* 8b "li r3, N; blr" returners. */
int Dummy3A_frameStart(void) { return 0x0; }

/* Pattern wrappers. */
extern u8 lbl_803DD728;
void Dummy39_initialise(void) { lbl_803DD728 = 0x28; }

extern u32 lbl_803DD72C;
extern void textureFree(u32);
void Dummy39_release(void) { textureFree(lbl_803DD72C); }

extern u32 lbl_803DD714, lbl_803DD718, lbl_803DD71C;
extern void warpToMap(int mapId, int spawnId);
extern void cutsceneExit(void);
extern void buttonDisable(int index, int flags);
extern f32 timeDelta;
extern f32 lbl_803E1DF0;
extern s8 lbl_803DD712;
extern s16 lbl_803DD710;
extern u8 lbl_803DD713;
extern u32 lbl_8031AD20[];
#pragma scheduling off
#pragma peephole off
int WeirdUnusedMenu_run(void)
{
    int selection;
    int action;

    if (lbl_803DD713 == 0)
    {
        selection = (*(int (*)(void))(*(int*)(*gTitleMenuLinkInterface + 0xc)))();
        action = (*(int (*)(void))(*(int*)(*gTitleMenuLinkInterface + 0x14)))();
        if (selection == 1)
        {
            if (action == 0)
            {
                Sfx_PlayFromObject(0, SFXqu_longsob2);
                loadUiDll(1);
                cutsceneExit();
                buttonDisable(0, 0x300);
            }
            else
            {
                Sfx_PlayFromObject(0, SFXqu_shortsob1);
                lbl_803DD712 = 0;
                lbl_803DD713 = 1;
                ((WeirdMenuWork*)lbl_8031AD20)->unk16 =
                    (u16)(((WeirdMenuWork*)lbl_8031AD20)->unk16 | 0x1000);
                ((WeirdMenuWork*)lbl_8031AD20)->unk52 =
                    (u16)(((WeirdMenuWork*)lbl_8031AD20)->unk52 | 0x1000);
                (*(void (*)(void))(*(int*)(*gTitleMenuLinkInterface + 0x2c)))();
            }
        }
        else if (selection == 0)
        {
            Sfx_PlayFromObject(0, 0x419);
            loadUiDll(1);
            cutsceneExit();
            buttonDisable(0, 0x300);
        }
    }
    else if (lbl_803DD713 == 1)
    {
        if ((s8)lbl_803DD712 == 0)
        {
            saveGame_save();
        }
        *(char*)&lbl_803DD712 = (int)
        ((f32)(s8)
        lbl_803DD712 + timeDelta
        )
        ;
        if ((f32)(s8)lbl_803DD712 >= lbl_803E1DF0
        )
        {
            lbl_803DD713 = 0;
            ((WeirdMenuWork*)lbl_8031AD20)->unk16 =
                (u16)(((WeirdMenuWork*)lbl_8031AD20)->unk16 & ~0x1000);
            ((WeirdMenuWork*)lbl_8031AD20)->unk52 =
                (u16)(((WeirdMenuWork*)lbl_8031AD20)->unk52 & ~0x1000);
            (*(void (*)(void))(*(int*)(*gTitleMenuLinkInterface + 0x2c)))();
            (*(void (*)(int))(*(int*)(*gTitleMenuLinkInterface + 0x18)))(0);
        }
    }

    lbl_803DD710 = (s16)(lbl_803DD710 + (framesThisStep << 3));
    if (lbl_803DD710 > 0x8c)
    {
        lbl_803DD710 = 0x8c;
    }
    return 0;
}

void WeirdUnusedMenu_release(void)
{
    textureFree(lbl_803DD71C);
    textureFree(lbl_803DD718);
    textureFree(lbl_803DD714);
    warpToMap(0, 1);
    (*(void (*)(void))(*(int*)(*gTitleMenuLinkInterface + 0x8)))();
}

extern u32 lbl_803DD720;
extern u32 lbl_8031AD98[];
extern u32 textureLoadAsset(int);
extern int Obj_GetPlayerObject(void);

int Dummy39_run(void)
{
    s32 v;
    u8 cur;
    s8 next;
    Obj_GetPlayerObject();
    v = framesThisStep;
    if (v > 3) v = 3;
    cur = lbl_803DD728;
    if ((s8)cur > 0)
    {
        next = (s8)(cur - v);
        *(s8*)&lbl_803DD728 = next;
        if ((s8)(u8)next <= 0
        )
        {
            loadUiDll(1);
            warpToMap(0x60, 1);
        }
    }
    return 0;
}

extern s16 lbl_803DD8C2;
extern void Sfx_PlayFromObjectLimited(int obj, u16 sfx, int);
#pragma peephole on
void cMenuPlaySelectedItemSfx(int obj)
{
    int sfx = 0;
    switch (lbl_803DD8C2)
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
        Sfx_PlayFromObjectLimited(obj, (u16)sfx, 1);
    }
}

void WeirdUnusedMenu_initialise(void)
{
    lbl_803DD71C = textureLoadAsset(0x31e);
    lbl_803DD718 = textureLoadAsset(0x310);
    lbl_803DD714 = textureLoadAsset(0x31f);
    lbl_803DD720 = gameTextGet(0);
    (*(void (*)(u32*, int, int, u32*, int, int, int, int, int, int, int, int))(*(int*)(*gTitleMenuLinkInterface +
        0x4)))(
        lbl_8031AD20, 2, 0, lbl_8031AD98, 0, 0, 0x5b, 0x45, 0x30, 0xff, 0xd7, 0x3d);
    lbl_803DD710 = 0;
    lbl_803DD713 = 0;
}
