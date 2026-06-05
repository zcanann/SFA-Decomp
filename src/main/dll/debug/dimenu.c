#include "ghidra_import.h"
#include "main/dll/debug/dimenu.h"
#include "main/audio/sfx_ids.h"

#define SFXsp_sa_off03 0xfc
#define SFXqu_longsob2 0x103
#define SFXqu_shortsob1 0x104

extern undefined4 FUN_800067e8();
extern undefined4 FUN_80006824();
extern undefined8 FUN_80006b84();
extern undefined4 FUN_80006ba8();
extern undefined4 FUN_80006c20();
extern undefined4 FUN_80006c88();
extern void* FUN_80006c9c();
extern void* FUN_80017470();
extern undefined8 FUN_80017484();
extern undefined4 FUN_80017488();
extern undefined4 FUN_800174d4();
extern undefined4 FUN_80017500();
extern undefined4 FUN_800176cc();
extern undefined4 FUN_80017a98();
extern undefined8 FUN_80053754();
extern undefined4 FUN_8005398c();
extern undefined4 FUN_80053aa4();
extern undefined4 FUN_80053c98();
extern undefined4 FUN_8005d018();
extern undefined4 FUN_8005d090();
extern undefined4 FUN_8005d17c();
extern undefined4 saveFileStruct_setCheatActive();
extern undefined4 saveFileStruct_isCheatActive();
extern uint isCheatUnlocked();
extern u8 *getSaveFileStruct();
extern void saveGame_save();
extern undefined4 FUN_8011bfc8();
extern undefined4 languageMenuInit();
extern int fn_8011C51C(int selection, int item);
extern undefined4 FUN_80133790();
extern char FUN_801339f8();
extern undefined4 FUN_80133a68();
extern undefined4 FUN_80133c3c();
extern undefined4 FUN_80134830();
extern undefined4 FUN_801348c0();
extern uint countLeadingZeros();

extern undefined4 DAT_8031b912;
extern undefined4 DAT_8031b914;
extern undefined4 DAT_8031b930;
extern undefined4 DAT_8031b970;
extern undefined4 DAT_8031b986;
extern undefined4 DAT_8031b9c2;
extern undefined4 DAT_8031b9e8;
extern int DAT_803a9430;
extern undefined4 DAT_803a9434;
extern undefined4 DAT_803a9438;
extern undefined4 DAT_803a943c;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc690;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd720;
extern undefined4* DAT_803dd724;
extern undefined4 DAT_803de378;
extern undefined4 DAT_803de379;
extern undefined4 DAT_803de380;
extern undefined4 DAT_803de384;
extern undefined4 DAT_803de385;
extern undefined4 DAT_803de386;
extern undefined4 DAT_803de388;
extern undefined4 DAT_803de38c;
extern undefined4 DAT_803de390;
extern undefined4 DAT_803de392;
extern undefined4 DAT_803de393;
extern undefined4 DAT_803de394;
extern undefined4 DAT_803de398;
extern undefined4 DAT_803de39c;
extern undefined4 DAT_803de3a0;
extern undefined4 DAT_803de3a8;
extern undefined4 DAT_803de542;
extern f64 DOUBLE_803e2a68;
extern f64 DOUBLE_803e2a78;
extern f32 lbl_803DC074;
extern f32 lbl_803E2A54;
extern f32 lbl_803E2A58;
extern f32 lbl_803E2A5C;
extern f32 lbl_803E2A60;
extern f32 lbl_803E2A64;
extern f32 lbl_803E2A70;
extern undefined4* PTR_DAT_8031b928;

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
extern void **gScreenTransitionInterface;
extern int *gTitleMenuItemInterface;
extern int *gTitleMenuLinkInterface;
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
extern void gameTextSetDrawFunc(void *fn);
extern void gameTextBoxFn_80134d40(int alpha, int p2, int p3);
extern void gameTextSetColor(int r, int g, int b, int a);
extern u32 gameTextGet(int textId);
extern void *gameTextGetBox(int boxId);
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
    int *item;
    u16 *panel = &lbl_8031ACB8[(s8)lbl_803DBA28 * 8];

    if (shouldShowCredits() != 0) {
        creditsStart_();
        return;
    }

    alpha = (int)(lbl_803E1DD4 -
                  ((f32 (*)(void))((void **)*gScreenTransitionInterface)[6])());
    gameTextSetDrawFunc(titleScreenTextDrawFunc);

    if ((u8)alpha < 0x80) {
        titleScreenPositionElements(lbl_803E1DD8,
            -((f32)((u8)alpha * 0x86) * lbl_803E1DE0 - lbl_803E1DDC));
        fade = 0;
    } else {
        titleScreenPositionElements(lbl_803E1DD8, lbl_803E1DE4);
        fade = (((u8)alpha & 0x7f) << 1);
    }

    gameTextBoxFn_80134d40(fade, 0, 0);
    if (panel[5] != 0xffff) {
        gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        *(u8 *)((char *)gameTextGetBox(*(u8 *)((char *)gameTextGet(panel[5]) + 4)) + 0x1e) = (u8)fade;
        gameTextShow(panel[5]);
    }
    if (panel[6] != 0xffff) {
        gameTextSetColor(0xff, 0xff, 0xff, fade);
        gameTextShow(panel[6]);
    }

    item = lbl_803A87D0;
    for (i = 0; i < 8; i++, item++) {
        if (*item != 0) {
            (*(void (*)(int, int, int))(*(int *)(*gTitleMenuItemInterface + 0x18)))(*item, arg, fade);
        }
    }
    (*(void (*)(int))(*(int *)(*gTitleMenuLinkInterface + 0x30)))(fade);
    (*(void (*)(int))(*(int *)(*gTitleMenuLinkInterface + 0x10)))(arg);
    gameTextSetDrawFunc(0);
    titleScreenShowCopyright(0);
    lbl_803DD706--;
    if ((s8)lbl_803DD706 < 0) {
        lbl_803DD706 = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void gameTextLoadDir(int);
extern u8 lbl_803DD70C;
extern u32 lbl_803DD708;
extern s8 lbl_803DD706;
extern u8 lbl_803DD705;
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
extern void fn_8011BFC8(int selection, int item);
extern void fn_8011C318(int selection, int item);
extern u8 framesThisStep;
extern void Sfx_PlayFromObject(int obj, int sfxId);
#pragma scheduling off
#pragma peephole off
void OptionsScreen_initialise(void)
{
    ((void (*)(int, int))((void **)*gScreenTransitionInterface)[3])(20, 5);
    gameTextLoadDir(21);
    lbl_803DD70C = 0;
    lbl_803DD708 = (u32)getSaveFileStruct();
    if (lbl_803DD6F8 == 0) {
        fn_8011CA74();
    } else if (lbl_803DD6F8 == 1) {
        fn_8011C7B4();
    } else {
        languageMenuInit();
    }
    lbl_803DD706 = 2;
    lbl_803DD705 = 0;
    lbl_803DD6F9 = 0;
}
#pragma peephole reset
#pragma scheduling reset

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
int OptionsScreen_run(void)
{
    int step = framesThisStep;
    s8 oldFade = lbl_803DD704;
    int selection;
    int item;
    int i;
    int *slot;

    if (shouldShowCredits()) {
        return 0;
    }
    if (step > 3) {
        step = 3;
    }
    if (lbl_803DD704 > 0) {
        lbl_803DD704 = (s8)(lbl_803DD704 - step);
    }
    if (((int (*)(void))(*(int *)((int)*gScreenTransitionInterface + 0x14)))() == 0) {
        (*(void (*)(void))(*(int *)(*gTitleMenuLinkInterface + 0x34)))();
        lbl_803DD706 = 2;
    }

    if (lbl_803DD705 != 0) {
        if ((oldFade <= 0xc || lbl_803DD704 > 0xc) && lbl_803DD704 <= 0) {
            if ((s8)lbl_803DBA28 != -1) {
                (*(void (*)(void))(*(int *)(*gTitleMenuLinkInterface + 0x8)))();
                lbl_803DBA28 = -1;
            }
            slot = lbl_803A87D0;
            for (i = 0; i < 8; i++, slot++) {
                if (*slot != 0) {
                    (*(void (*)(int))(*(int *)(*gTitleMenuItemInterface + 0x10)))(*slot);
                    *slot = 0;
                }
            }
            titleScreenFn_8005cdd4(1);
            setDrawCloudsAndLights(1);
            loadUiDll(4);
        }
        return (uint)((uint)(int)lbl_803DD704 < 0xd) - ((int)lbl_803DD704 >> 0x1f);
    }

    selection = (*(int (*)(void))(*(int *)(*gTitleMenuLinkInterface + 0xc)))();
    item = (*(int (*)(void))(*(int *)(*gTitleMenuLinkInterface + 0x14)))();
    if (item != lbl_803DD700) {
        Sfx_PlayFromObject(0, SFXsp_sa_off03);
    }
    lbl_803DD700 = item;

    switch ((s8)lbl_803DBA28) {
        case 0:
            lbl_803DD70C = (s8)item;
            if (fn_8011C51C(selection, item) != 0) {
                return 0;
            }
            break;
        case 2:
            fn_8011C318(selection, item);
            if (selection == 0) {
                ((u8 *)lbl_803DD708)[6] =
                    (*(int (*)(int))(*(int *)(*gTitleMenuItemInterface + 0x24)))(lbl_803A87D0[0]);
                ((u8 *)lbl_803DD708)[8] =
                    !(*(int (*)(int))(*(int *)(*gTitleMenuItemInterface + 0x24)))(lbl_803A87D0[1]);
                setWidescreen(((u8 *)lbl_803DD708)[6]);
                setRumbleEnabled(((u8 *)lbl_803DD708)[8]);
            }
            break;
        case 1:
            fn_8011BFC8(selection, item);
            if (selection == 0) {
                ((u8 *)lbl_803DD708)[9] =
                    (*(int (*)(int))(*(int *)(*gTitleMenuItemInterface + 0x24)))(lbl_803A87D0[0]);
                ((u8 *)lbl_803DD708)[10] =
                    (*(int (*)(int))(*(int *)(*gTitleMenuItemInterface + 0x24)))(lbl_803A87D0[1]);
                ((u8 *)lbl_803DD708)[11] =
                    (*(int (*)(int))(*(int *)(*gTitleMenuItemInterface + 0x24)))(lbl_803A87D0[2]);
                ((u8 *)lbl_803DD708)[12] =
                    (*(int (*)(int))(*(int *)(*gTitleMenuItemInterface + 0x24)))(lbl_803A87D0[3]);
            }
            break;
        case 3:
            if (selection == 0) {
                Sfx_PlayFromObject(0, SFXsp_snrot1_c);
                (*(void (*)(int, int))(*(int *)((int)*gScreenTransitionInterface + 0x8)))(0x14, 5);
                lbl_803DD704 = 0x23;
                lbl_803DD705 = 1;
            }
            if (lbl_803A87D0[item] != 0 &&
                (*(int (*)(int))(*(int *)(*gTitleMenuItemInterface + 0x2c)))(lbl_803A87D0[item]) != 0) {
                if (item == 0) {
                    ((u8 *)lbl_803DD708)[2] =
                        !(*(int (*)(int))(*(int *)(*gTitleMenuItemInterface + 0x24)))(lbl_803A87D0[0]);
                    setSubtitlesEnabled(((u8 *)lbl_803DD708)[2]);
                } else {
                    saveFileStruct_setCheatActive(3,
                        !(*(int (*)(int))(*(int *)(*gTitleMenuItemInterface + 0x24)))(lbl_803A87D0[item]));
                }
            }
            break;
    }

    if ((s8)lbl_803DBA28 != 0) {
        slot = lbl_803A87D0;
        for (i = 0; i < 8; i++, slot++) {
            if (*slot != 0) {
                (*(void (*)(int, int))(*(int *)(*gTitleMenuItemInterface + 0x20)))(*slot, i == item);
                (*(void (*)(int))(*(int *)(*gTitleMenuItemInterface + 0x14)))(*slot);
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
void FUN_8011d67c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  undefined8 uVar1;
  
  uVar1 = (**(code **)(*DAT_803dd6cc + 0xc))(0x14,5);
  FUN_80017488(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x15);
  DAT_803de38c = 0;
  DAT_803de388 = (undefined4)getSaveFileStruct();
  if (DAT_803de378 == '\0') {
    OptionsScreen_render(0);
  }
  else if (DAT_803de378 == '\x01') {
    fn_8011C7B4();
  }
  else {
    fn_8011CA74();
  }
  DAT_803de386 = 2;
  DAT_803de385 = 0;
  DAT_803de379 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011d9f4
 * EN v1.0 Address: 0x8011D9F4
 * EN v1.0 Size: 260b
 * EN v1.1 Address: 0x8011DA30
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011d9f4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  undefined8 uVar1;
  
  FUN_80053754();
  FUN_80053754();
  uVar1 = FUN_80053754();
  FUN_80053c98(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,'\x01',param_11,
               param_12,param_13,param_14,param_15,param_16);
  (**(code **)(*DAT_803dd720 + 8))();
  return;
}

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
void FUN_8011daf8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
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
FUN_8011dafc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
            undefined4 param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  byte bVar1;
  undefined8 uVar2;
  
  FUN_80017a98();
  bVar1 = DAT_803dc070;
  if (3 < DAT_803dc070) {
    bVar1 = 3;
  }
  if (('\0' < DAT_803de3a8) && (DAT_803de3a8 = DAT_803de3a8 - bVar1, DAT_803de3a8 < '\x01')) {
    uVar2 = FUN_80006b84(1);
    FUN_80053c98(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x60,'\x01',param_11,
                 param_12,param_13,param_14,param_15,param_16);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8011dc20
 * EN v1.0 Address: 0x8011DC20
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x8011DBB4
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011dc20(void)
{
  FUN_80053754();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011dc40
 * EN v1.0 Address: 0x8011DC40
 * EN v1.0 Size: 144b
 * EN v1.1 Address: 0x8011DBFC
 * EN v1.1 Size: 152b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011dc40(uint param_1)
{
  ushort uVar1;
  
  uVar1 = 0;
  if (DAT_803de542 == 3) {
    uVar1 = 0x3fc;
  }
  else if (DAT_803de542 < 3) {
    if (DAT_803de542 == 1) {
      uVar1 = 0x3f8;
    }
    else if (DAT_803de542 < 1) {
      if (-1 < DAT_803de542) {
        uVar1 = 0x3fb;
      }
    }
    else {
      uVar1 = 0x3f7;
    }
  }
  else if (DAT_803de542 == 5) {
    uVar1 = 0x3fa;
  }
  else if (DAT_803de542 < 5) {
    uVar1 = 0x3f9;
  }
  if (uVar1 != 0) {
    FUN_800067e8(param_1,uVar1,1);
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void OptionsScreen_frameEnd(void) {}
void OptionsScreen_release(void) {}
void WeirdUnusedMenu_render(void) {}
void WeirdUnusedMenu_frameEnd(void) {}
void Dummy39_render(void) {}
void Dummy39_frameEnd(void) {}
void Dummy3A_render(void) {}
void Dummy3A_frameEnd(void) {}
void Dummy3A_release(void) {}
void Dummy3A_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int Dummy3A_frameStart(void) { return 0x0; }

/* Pattern wrappers. */
extern u8 lbl_803DD728;
void Dummy39_initialise(void) { lbl_803DD728 = 0x28; }

extern u32 lbl_803DD72C;
extern void textureFree(u32);
#pragma scheduling off
#pragma peephole off
void Dummy39_release(void) { textureFree(lbl_803DD72C); }
#pragma peephole reset
#pragma scheduling reset

extern u32 lbl_803DD714, lbl_803DD718, lbl_803DD71C;
extern int *gTitleMenuLinkInterface;
extern void warpToMap(int mapId, int spawnId);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void cutsceneExit(void);
extern void buttonDisable(int index, int flags);
extern f32 timeDelta;
extern f32 lbl_803E1DF0;
extern s8 lbl_803DD712;
extern s16 lbl_803DD710;
extern u8 lbl_803DD713;
extern u32 lbl_8031AD20[];
extern u8 framesThisStep;
extern void loadUiDll(int);
#pragma scheduling off
#pragma peephole off
int WeirdUnusedMenu_run(void) {
    int selection;
    int action;

    if (lbl_803DD713 == 0) {
        selection = (*(int (*)(void))(*(int *)(*gTitleMenuLinkInterface + 0xc)))();
        action = (*(int (*)(void))(*(int *)(*gTitleMenuLinkInterface + 0x14)))();
        if (selection == 1) {
            if (action == 0) {
                Sfx_PlayFromObject(0, SFXqu_longsob2);
                loadUiDll(1);
                cutsceneExit();
                buttonDisable(0, 0x300);
            } else {
                Sfx_PlayFromObject(0, SFXqu_shortsob1);
                lbl_803DD712 = 0;
                lbl_803DD713 = 1;
                *(u16 *)((char *)lbl_8031AD20 + 0x16) =
                    (u16)(*(u16 *)((char *)lbl_8031AD20 + 0x16) | 0x1000);
                *(u16 *)((char *)lbl_8031AD20 + 0x52) =
                    (u16)(*(u16 *)((char *)lbl_8031AD20 + 0x52) | 0x1000);
                (*(void (*)(void))(*(int *)(*gTitleMenuLinkInterface + 0x2c)))();
            }
        } else if (selection == 0) {
            Sfx_PlayFromObject(0, 0x419);
            loadUiDll(1);
            cutsceneExit();
            buttonDisable(0, 0x300);
        }
    } else if (lbl_803DD713 == 1) {
        if ((s8)lbl_803DD712 == 0) {
            saveGame_save();
        }
        *(char *)&lbl_803DD712 = (int)((f32)(s8)lbl_803DD712 + timeDelta);
        if ((f32)(s8)lbl_803DD712 >= lbl_803E1DF0) {
            lbl_803DD713 = 0;
            *(u16 *)((char *)lbl_8031AD20 + 0x16) =
                (u16)(*(u16 *)((char *)lbl_8031AD20 + 0x16) & ~0x1000);
            *(u16 *)((char *)lbl_8031AD20 + 0x52) =
                (u16)(*(u16 *)((char *)lbl_8031AD20 + 0x52) & ~0x1000);
            (*(void (*)(void))(*(int *)(*gTitleMenuLinkInterface + 0x2c)))();
            (*(void (*)(int))(*(int *)(*gTitleMenuLinkInterface + 0x18)))(0);
        }
    }

    lbl_803DD710 = (s16)(lbl_803DD710 + (framesThisStep << 3));
    if (lbl_803DD710 > 0x8c) {
        lbl_803DD710 = 0x8c;
    }
    return 0;
}

void WeirdUnusedMenu_release(void) {
    textureFree(lbl_803DD71C);
    textureFree(lbl_803DD718);
    textureFree(lbl_803DD714);
    warpToMap(0, 1);
    (*(void (*)(void))(*(int *)(*gTitleMenuLinkInterface + 0x8)))();
}
#pragma peephole reset
#pragma scheduling reset

extern u32 lbl_803DD720;
extern s16 lbl_803DD710;
extern u8 lbl_803DD713;
extern u32 lbl_8031AD20[];
extern u32 lbl_8031AD98[];
extern u32 textureLoadAsset(int);
extern u32 gameTextGet(int);
extern int Obj_GetPlayerObject(void);
extern u8 framesThisStep;
extern void loadUiDll(int);
#pragma scheduling off
#pragma peephole off
int Dummy39_run(void) {
    s32 v;
    u8 cur;
    s8 next;
    Obj_GetPlayerObject();
    v = framesThisStep;
    if (v > 3) v = 3;
    cur = lbl_803DD728;
    if ((s8)cur > 0) {
        next = (s8)(cur - v);
        *(s8 *)&lbl_803DD728 = next;
        if ((s8)(u8)next <= 0) {
            loadUiDll(1);
            warpToMap(0x60, 1);
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern s16 lbl_803DD8C2;
extern void Sfx_PlayFromObjectLimited(int obj, u16 sfx, int);
#pragma scheduling off
#pragma peephole off
void cMenuPlaySelectedItemSfx(int obj) {
    int sfx = 0;
    switch (lbl_803DD8C2) {
        case 0: sfx = 0x3FB; break;
        case 5: sfx = 0x3FA; break;
        case 1: sfx = 0x3F8; break;
        case 4: sfx = 0x3F9; break;
        case 2: sfx = 0x3F7; break;
        case 3: sfx = 0x3FC; break;
    }
    if (sfx != 0) {
        Sfx_PlayFromObjectLimited(obj, (u16)sfx, 1);
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void WeirdUnusedMenu_initialise(void) {
    lbl_803DD71C = textureLoadAsset(0x31e);
    lbl_803DD718 = textureLoadAsset(0x310);
    lbl_803DD714 = textureLoadAsset(0x31f);
    lbl_803DD720 = gameTextGet(0);
    (*(void (*)(u32 *, int, int, u32 *, int, int, int, int, int, int, int, int))(*(int *)(*gTitleMenuLinkInterface + 0x4)))(
        lbl_8031AD20, 2, 0, lbl_8031AD98, 0, 0, 0x5b, 0x45, 0x30, 0xff, 0xd7, 0x3d);
    lbl_803DD710 = 0;
    lbl_803DD713 = 0;
}
#pragma peephole reset
#pragma scheduling reset
