#include "ghidra_import.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/dll_47.h"
#include "main/dll/FRONT/frontend_control.h"
#include "main/dll/FRONT/title_menu.h"



#pragma peephole off
#pragma scheduling off
typedef struct SaveSelectPanel {
    TitleMenuTextEntry *entries;
    u8 count;
    u8 pad5;
    u16 textIdA;
    u16 textIdB;
    u8 padA[2];
} SaveSelectPanel;

extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void textureFree(void *resource);
extern void doNothing_onSaveSelectScreenExit(void);
extern void loadUiDll(int id);
extern void *mmAlloc(int size, int heap, int flags);
extern void *textureLoadAsset(int id);
extern void gameTextLoadDir(int dirId);
extern void *gameTextGet(int id);
extern int getUiDllFn_80014930(void);

extern s8 lbl_803DB9FB;
extern u8 lbl_803DB424;
extern s8 saveFileSelect_currentSlotIndex;
extern u8 saveFileSelect_saveDirty;
extern u8 saveFileSelect_debugCheatProgress;
extern u8 saveFileSelect_saveCheatProgress;
extern u8 saveFileSelect_cheatInputTimer;
extern TitleMenuControl *gScreenTransitionInterface;
extern TitleMenuControl *gTitleMenuControlInterface;
extern TitleMenuControl *gTitleMenuLinkInterface;
extern TitleMenuControl *gTitleMenuItemInterface;
extern void *lbl_803DD6A0;
extern void *lbl_803DD6AC;
extern void *lbl_803DD6B8;
extern u8 lbl_803DD6B4;
extern int lbl_803DD6C0;
extern void *lbl_803DD6C8;
extern u8 lbl_803DD6C5;
extern u8 lbl_803DD6CC;
extern u8 lbl_803DD6CD;
extern s8 lbl_803DD6CE;
extern s8 lbl_803DD6CF;
extern u8 lbl_803DD6C4;
extern void *lbl_8031A804[4];
extern void *lbl_803A8680[4];
extern SaveSelectPanel lbl_8031A7BC[8];
extern u8 lbl_8031A7F8[];
extern s16 lbl_803DBA04;

extern undefined4 FUN_80003494();
extern undefined4 FUN_800067c0();
extern undefined8 FUN_80006824();
extern undefined4 FUN_80006b84();
extern uint FUN_80006c00();
extern uint FUN_80006c3c();
extern undefined4 FUN_80006c64();
extern undefined8 FUN_80006c6c();
extern undefined4 FUN_80006c88();
extern undefined8 FUN_80017484();
extern undefined4 FUN_800174d4();
extern undefined4 FUN_8001767c();
extern undefined4 FUN_80017814();
extern undefined4 FUN_80017818();
extern undefined8 FUN_80043030();
extern undefined4 FUN_80053754();
extern void gplaySaveGame();
void saveSelectGoToChapterSelect(void);
void saveSelectGoToChooseSlot(int arg);
extern undefined4 FUN_800e8ba4();
extern undefined4 FUN_800e8f58();
extern undefined4 FUN_800e9298();
extern undefined8 n_attractmode_releaseMovieBuffers();
extern undefined4 FUN_80119d90();
extern undefined4 saveSelectSetSlot();
extern undefined4 FUN_80133a68();
extern undefined8 FUN_80133c3c();
extern undefined4 FUN_80134830();
extern undefined4 FUN_801348c0();
extern undefined8 creditsStart();
extern undefined4 FUN_80286830();
extern undefined4 FUN_8028687c();
extern undefined8 FUN_8028fde8();
extern undefined4 FUN_80294d64();
extern uint countLeadingZeros();

extern undefined4 DAT_8031b410;
extern undefined4 DAT_8031b412;
extern undefined4 DAT_8031b414;
extern undefined4 DAT_8031b41c;
extern undefined4 DAT_8031b440;
extern undefined4 DAT_8031b448;
extern undefined4 DAT_8031b454;
extern int DAT_803a92b8;
extern int DAT_803a92e0;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc084;
extern undefined4 DAT_803dc650;
extern byte DAT_803dc658;
extern undefined4 DAT_803dc65b;
extern undefined4 DAT_803dc65c;
extern undefined4 DAT_803dc67c;
extern undefined4 DAT_803dc680;
extern undefined4 DAT_803dc684;
extern undefined4 DAT_803dc688;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6f0;
extern undefined4* DAT_803dd720;
extern undefined4* DAT_803dd724;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803de110;
extern undefined4 DAT_803de320;
extern undefined4 DAT_803de324;
extern undefined4 DAT_803de325;
extern undefined4 DAT_803de328;
extern undefined4 DAT_803de32c;
extern undefined4 DAT_803de330;
extern undefined4 DAT_803de338;
extern undefined4 DAT_803de33c;
extern undefined4 DAT_803de33d;
extern undefined4 DAT_803de33e;
extern undefined4 DAT_803de340;
extern undefined4 DAT_803de344;
extern undefined4 DAT_803de345;
extern undefined4 DAT_803de34c;
extern undefined4 DAT_803de34d;
extern undefined4 DAT_803de34e;
extern undefined4 DAT_803de34f;
extern f64 DOUBLE_803e29f8;
extern f32 lbl_803E29E4;
extern f32 lbl_803E29E8;
extern f32 lbl_803E29EC;
extern f32 lbl_803E29F0;
extern f32 lbl_803E29F4;
extern undefined4* PTR_DAT_8031b40c;
extern undefined4* PTR_DAT_8031b418;
extern undefined4* PTR_DAT_8031b43c;
extern char s__savegame_save_d_bin_8031b4b4[];
extern void mm_free(void *p);
extern void *lbl_803A8658[10];
extern FrontendSaveSlot *saveFileSelect_saveSlotsBase;
extern FrontendSaveSlot *saveFileSelect_saveSlots;
extern int lbl_803DB9FC;
extern u8 lbl_803DB424;
extern char sFrontendStringFormat;
extern char lbl_803DBA20;
extern int saveSelect_getInfo(void);
extern int sprintf(char *dst, const char *fmt, ...);

/*
 * --INFO--
 *
 * Function: saveSelectOpenFile
 * EN v1.0 Address: 0x8011A0DC
 * EN v1.0 Size: 444b
 * EN v1.1 Address: 0x8011A254
 * EN v1.1 Size: 304b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma dont_inline on
void saveSelectOpenFile(int sel, int slot)
{
  TitleMenuTextEntry **pp;
  int off;

  off = lbl_803DB9FB * 0xc;
  pp = (TitleMenuTextEntry **)lbl_8031A7BC;
  if (sel == 0) {
    if (lbl_803DD6B8 != NULL) {
      ((void (**)(void))gTitleMenuItemInterface->vtable)[4]();
      lbl_803DD6B8 = NULL;
    }
    Sfx_PlayFromObject(0,0x419);
    saveSelectGoToChooseSlot(0);
  }
  else {
    Sfx_PlayFromObject(0,0x418);
    if (lbl_803DD6C5 == 0) {
      if (slot == 0) {
        saveSelectGoToChapterSelect();
      }
      else {
        (*(TitleMenuTextEntry **)((char *)pp + off))->flags =
            (u16)((*(TitleMenuTextEntry **)((char *)pp + off))->flags | 0x4000);
        *(s8 *)((char *)*(TitleMenuTextEntry **)((char *)pp + off) + 0x56) = -1;
        *(u16 *)((char *)*(TitleMenuTextEntry **)((char *)pp + off) + 0x3c) = 984;
        lbl_803DD6C5 = 1;
        lbl_803DD6B8 =
             ((void *(**)(int, int, int, int, int))gTitleMenuItemInterface->vtable)[3]
                 (983,41,0,1,0);
        ((void (**)(void *, int))gTitleMenuItemInterface->vtable)[8](lbl_803DD6B8,1);
        ((void (**)(TitleMenuTextEntry *))gTitleMenuLinkInterface->vtable)[11](*(TitleMenuTextEntry **)((char *)pp + off));
      }
    }
    else {
      if (((u8 (**)(void *))gTitleMenuItemInterface->vtable)[9](lbl_803DD6B8) == 1) {
        gplaySaveGame((u8)saveFileSelect_currentSlotIndex);
      }
      ((void (**)(void *))gTitleMenuItemInterface->vtable)[4](lbl_803DD6B8);
      lbl_803DD6B8 = NULL;
      saveSelectGoToChooseSlot(0);
    }
  }
}
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: SaveSelectScreen_release
 * EN v1.0 Address: 0x8011B354
 * EN v1.0 Size: 96b
 */
#pragma scheduling off
void SaveSelectScreen_release(void) {
    void **p;
    int i;
    void *zero;

    i = 0;
    p = lbl_803A8658;
    zero = NULL;
    do {
        mm_free(*p);
        *p = zero;
        p++;
        i++;
    } while (i < 10);
}
#pragma scheduling reset

/* Stubs for as-yet-unmatched functions. */
#pragma dont_inline on
void saveFileSelect_init(int param_1, int param_2)
{
  int i;

  saveFileSelect_saveSlots = saveFileSelect_saveSlotsBase;
  if (param_1 == 0) {
    Sfx_PlayFromObject(0, SFXsp_snrot1_c);
    ((void (**)(int, int))gScreenTransitionInterface->vtable)[2](20, 5);
    lbl_803DD6CF = 0x23;
    lbl_803DD6CC = 1;
  }
  else if (param_1 != -1) {
    if (param_1 == 1) {
      saveFileSelect_currentSlotIndex = (s8)param_2;
      i = (s8)param_2;
      if (*(u8 *)((char *)(saveFileSelect_saveSlots + i) + 0x20) == 0) {
        loadUiDll(6);
      }
      else {
        Sfx_PlayFromObject(0, 0x418);
        if ((s8)lbl_803DB9FB != -1) {
          ((void (**)(void))gTitleMenuLinkInterface->vtable)[2]();
        }
        lbl_803DB9FB = 1;
        *(u16 *)((char *)lbl_8031A7BC[1].entries + 0x16) =
             (u16)(*(u16 *)((char *)lbl_8031A7BC[1].entries + 0x16) & ~0x4000);
        *(s8 *)((char *)lbl_8031A7BC[1].entries + 0x56) = 0;
        *(u16 *)((char *)lbl_8031A7BC[1].entries + 0x3c) = 982;
        lbl_803DD6C5 = 0;
        ((void (**)(void *, u8, int, int, int, int, int, int, int, int, int, int))
             gTitleMenuLinkInterface->vtable)[1]
            (lbl_8031A7BC[1].entries, lbl_8031A7BC[1].count, 0, 0, 5, 4, 20, 200,
             255, 255, 255, 255);
        ((void (**)(int))gTitleMenuLinkInterface->vtable)[6](0);
        saveFileSelect_debugCheatProgress = 0;
        saveFileSelect_saveCheatProgress = 0;
        saveFileSelect_cheatInputTimer = 0;
        lbl_803DD6CE = 2;
      }
    }
  }
}
#pragma dont_inline reset
/*
 * --INFO--
 *
 * Function: saveSelectSetupMenuItems
 * EN v1.0 Address: 0x8011A410
 * EN v1.0 Size: 216b
 */
#pragma scheduling off
#pragma peephole off
void saveSelectSetupMenuItems(void **p) {
    int off1;
    int off2;
    int i;
    char *base;

    i = 0;
    off1 = 0;
    off2 = off1;
    while (i < (int)*(u8 *)((char *)p + 0x4)) {
        base = (char *)saveFileSelect_saveSlotsBase;
        saveFileSelect_saveSlots = (FrontendSaveSlot *)base;
        if (*(u8 *)(base + off1 + 0x20) == 0) {
            *(u16 *)((char *)*p + off2) = 0x39d;
            *(u16 *)((char *)*p + off2 + 0x16) = (u16)(*(u16 *)((char *)*p + off2 + 0x16) & ~0x1);
            *(u16 *)((char *)*p + off2 + 0x16) = (u16)(*(u16 *)((char *)*p + off2 + 0x16) | 0x2);
            *(int *)((char *)*p + off2 + 0x10) = -1;
        } else {
            *(u16 *)((char *)*p + off2) = (u16)i;
            *(u16 *)((char *)*p + off2 + 0x16) = (u16)(*(u16 *)((char *)*p + off2 + 0x16) & ~0x2);
            *(u16 *)((char *)*p + off2 + 0x16) = (u16)(*(u16 *)((char *)*p + off2 + 0x16) | 0x1);
            *(int *)((char *)*p + off2 + 0x10) = -1;
        }
        off1 += 0x24;
        off2 += 0x3c;
        i++;
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline on
void saveSelectGoToChapterSelect(void)
{
  int i;
  int off;

  if ((s8)lbl_803DB9FB != -1) {
    ((void (**)(void))gTitleMenuLinkInterface->vtable)[2]();
  }
  if (saveFileSelect_saveDirty != 0 || lbl_803DB424 == 0) {
    lbl_803DB9FB = 4;
    off = 0;
    for (i = 0; i < 6; i++) {
      if (i > *(u8 *)((char *)saveFileSelect_saveSlots +
                      (s8)saveFileSelect_currentSlotIndex * 36 + 33)) {
        *(u16 *)((char *)lbl_8031A7BC[4].entries + off + 22) =
             (u16)(*(u16 *)((char *)lbl_8031A7BC[4].entries + off + 22) | 0x4000);
      }
      else {
        *(u16 *)((char *)lbl_8031A7BC[4].entries + off + 22) =
             (u16)(*(u16 *)((char *)lbl_8031A7BC[4].entries + off + 22) & ~0x4000);
      }
      if (i <= *(u8 *)((char *)saveFileSelect_saveSlots +
                       (s8)saveFileSelect_currentSlotIndex * 36 + 33) + -1 && i < 5) {
        *(s8 *)((char *)lbl_8031A7BC[4].entries + off + 27) = (s8)(i + 1);
      }
      else {
        *(s8 *)((char *)lbl_8031A7BC[4].entries + off + 27) = -1;
      }
      off += 60;
    }
    ((void (**)(void *, u8, int, void *, int, int, int, int, int, int, int, int))
         gTitleMenuLinkInterface->vtable)[1]
        (lbl_8031A7BC[4].entries, lbl_8031A7BC[4].count, 0, lbl_8031A7F8, 5, 4, 0, 0,
         0, 0, 0, 0);
    lbl_803DD6CE = 2;
  }
  else {
    lbl_803DD6CD = 1;
    Sfx_PlayFromObject(0, 0x418);
    ((void (**)(int, int))gScreenTransitionInterface->vtable)[2](20, 1);
    ((void (**)(int))gTitleMenuControlInterface->vtable)[7](0);
    ((void (**)(int))gTitleMenuControlInterface->vtable)[7](1);
    ((void (**)(int))gTitleMenuControlInterface->vtable)[7](2);
    ((void (**)(int))gTitleMenuControlInterface->vtable)[7](3);
    lbl_803DD6CF = 0x23;
    lbl_803DD6C4 = 0;
  }
}
#pragma dont_inline reset
/*
 * --INFO--
 *
 * Function: saveSelectFn_8011a70c
 * EN v1.0 Address: 0x8011A70C
 * EN v1.0 Size: 216b
 */
#pragma scheduling off
#pragma dont_inline on
void saveSelectFn_8011a70c(void) {
    int i;
    int off;
    saveFileSelect_saveSlots = saveFileSelect_saveSlotsBase;
    lbl_803DB9FC = 0;
    if (lbl_803DB424 != 0) {
        saveSelect_getInfo();
        if (lbl_803DB424 != 0) {
            lbl_803DB9FC = 3;
        }
    }
    i = lbl_803DB9FC;
    off = i * 0x24;
    while (i < 3) {
        sprintf((char *)saveFileSelect_saveSlots + off, &sFrontendStringFormat, &lbl_803DBA20);
        *((u8 *)saveFileSelect_saveSlots + (off + 0x5)) = 0;
        *((u8 *)saveFileSelect_saveSlots + (off + 0x6)) = 0;
        *((u8 *)saveFileSelect_saveSlots + (off + 0x4)) = 0;
        *((int *)((char *)saveFileSelect_saveSlots + (off + 0x8))) = 0;
        *((u8 *)saveFileSelect_saveSlots + (off + 0x21)) = 0;
        off += 0x24;
        i++;
    }
}
#pragma dont_inline reset
#pragma scheduling reset
/*
 * --INFO--
 *
 * Function: saveSelectGoToChooseSlot
 * EN v1.0 Address: 0x8011A7E4
 * EN v1.0 Size: 304b
 */
#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void saveSelectGoToChooseSlot(int arg) {
    SaveSelectPanel *p;
    u8 i;

    if (lbl_803DB9FB != -1) {
        ((void (**)(void))gTitleMenuLinkInterface->vtable)[2]();
    }
    lbl_803DB9FB = 0;
    saveFileSelect_currentSlotIndex = 0;
    p = &lbl_8031A7BC[0];

    saveSelectFn_8011a70c();
    saveSelectSetupMenuItems((void **)p);

    for (i = 0; i < 1; i++) {
        if ((&lbl_803DB9FC)[i] != 3) {
            p->entries[0].pad18[2] = 3;
        } else {
            p->entries[0].pad18[2] = -1;
        }
    }

    ((void (**)(TitleMenuTextEntry *, int, int, int, int, int, int, int, int, int, int, int))
        gTitleMenuLinkInterface->vtable)[1](
        p->entries, p->count, 0, 0, 5, 4, 0x14, 0xc8,
        0xff, 0xff, 0xff, 0xff);

    ((void (**)(int))gTitleMenuLinkInterface->vtable)[6](0);

    lbl_803DD6CE = 2;
    if (lbl_803DB424 == 0) {
        saveSelectGoToChapterSelect();
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: saveSelectScreenFree
 * EN v1.0 Address: 0x8011A914
 * EN v1.0 Size: 316b
 */
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void saveSelectScreenFree(int param_1) {
    void **p;
    int i;
    void *zero;

    if (lbl_8031A804[0] != NULL) {
        mm_free(lbl_8031A804[0]);
        lbl_8031A804[0] = NULL;
    }
    lbl_803DD6A0 = 0;
    if (lbl_803DB9FB != -1) {
        ((void (**)(void))gTitleMenuLinkInterface->vtable)[2]();
        lbl_803DB9FB = -1;
    }
    if (saveFileSelect_saveSlotsBase != NULL) {
        mm_free(saveFileSelect_saveSlotsBase);
        saveFileSelect_saveSlotsBase = NULL;
    }
    if (lbl_803DD6AC != NULL) {
        mm_free(lbl_803DD6AC);
        lbl_803DD6AC = NULL;
    }

    i = 0;
    p = lbl_803A8680;
    zero = NULL;
    do {
        if (*p != NULL) {
            textureFree(*p);
            *p = zero;
        }
        p++;
        i++;
    } while (i < 4);

    textureFree(lbl_803DD6C8);
    if (param_1 != 0) {
        doNothing_onSaveSelectScreenExit();
    }
    if (lbl_803DD6B8 != NULL) {
        ((void (**)(void))gTitleMenuItemInterface->vtable)[4]();
        lbl_803DD6B8 = NULL;
    }
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset
extern void gameTextSetDrawFunc(void *fn);
extern void titleScreenTextDrawFunc(void);
extern void titleScreenPositionElements(f32 a, f32 b);
extern void gameTextBoxFn_80134d40(u8 a, u8 b, int c);
extern void gameTextSetColor(int r, int g, int b, u8 a);
extern void gameTextAppendStr(char *str, int textId);
extern void gameTextShow(int textId);
extern void titleScreenShowCopyright(int arg);
extern u8 lbl_803DB9F8;
extern u16 lbl_803DB9F0[4];
extern char sFrontendPercentFormat;
extern f32 lbl_803E1D64;
extern f32 lbl_803E1D68;
extern f32 lbl_803E1D6C;
extern f32 lbl_803E1D70;
extern f32 lbl_803E1D74;
extern u8 framesThisStep;
extern uint getButtonsJustPressed(int arg);
extern int mmSetFreeDelay(int delay);
extern void mapUnload(int mapId, u32 flags);
extern void Music_Trigger(int id, int arg);
extern void trySaveGame(int slot);
extern void gplayNewGame(char *name, int slot);
extern char *loadFileByPath(char *path, int a, int b);
extern void *memcpy(void *dst, void *src, int n);
extern void fn_80296B70(int arg);
extern void saveFileSelect_checkCheatCodes(void);
extern void titleScreenFn_801368d4(void);
extern TitleMenuControl *gMapEventInterface;
extern void *lbl_803DD498;
extern char sFrontendFoxName;
extern char sSaveGameBinPathFormat[];
extern void *lbl_803A8658[10];

/*
 * --INFO--
 *
 * Function: SaveSelectScreen_render
 * EN v1.0 Address: 0x8011AA50
 * EN v1.0 Size: 976b
 */
#pragma scheduling off
#pragma peephole off
void SaveSelectScreen_render(int param)
{
    SaveSelectPanel *panel;
    int v;
    u8 alpha;
    int i;
    int n;
    int off;
    char *p;
    u8 *strs;
    void **arr;
    u16 *ptrs;

    panel = &lbl_8031A7BC[lbl_803DB9FB];
    gameTextSetDrawFunc(titleScreenTextDrawFunc);
    v = (int)(lbl_803E1D64 - ((f32 (**)(void))gScreenTransitionInterface->vtable)[6]());
    if ((u8)v < 0x80) {
        titleScreenPositionElements(lbl_803E1D68, lbl_803E1D6C - (f32)(int)((u8)v * 0x86) * lbl_803E1D70);
        alpha = 0;
    } else {
        titleScreenPositionElements(lbl_803E1D68, lbl_803E1D74);
        alpha = (u8)(((u8)v & 0x7f) << 1);
    }
    gameTextBoxFn_80134d40(alpha, (u8)(lbl_803DB9FB == 3), 0);
    switch (lbl_803DB9FB) {
    case 1:
        saveSelect_drawText(param, alpha);
        gameTextSetColor(0xff, 0xff, 0xff, alpha);
        n = 0;
        p = (char *)saveFileSelect_saveSlots + saveFileSelect_currentSlotIndex * 0x24;
        while (n < 3 && *(int *)(p + 0xc) != 0) {
            p += 4;
            n++;
        }
        i = 0;
        strs = &lbl_803DB9F8 + (u8)(3 - n);
        off = 0;
        while (i < n) {
            gameTextAppendStr(*(char **)((char *)saveFileSelect_saveSlots + saveFileSelect_currentSlotIndex * 0x24 + off + 0xc), *strs);
            strs++;
            off += 4;
            i++;
        }
        if (lbl_803DD6B8 != NULL) {
            ((void (**)(void *, int, u8))gTitleMenuItemInterface->vtable)[6](lbl_803DD6B8, 0, alpha);
        }
        break;
    case 3:
        gameTextSetColor(0xff, 0xff, 0xff, alpha);
        gameTextShow(0x324);
        break;
    case 0:
        gameTextSetColor(0xff, 0xff, 0xff, alpha);
        ((void (**)(void))gTitleMenuLinkInterface->vtable)[5]();
        if (lbl_803DB424 != 0) {
            saveFileSelect_saveSlots = saveFileSelect_saveSlotsBase;
            i = 0;
            off = 0;
            arr = lbl_803A8658;
            ptrs = lbl_803DB9F0;
            do {
                sprintf(*arr, &sFrontendPercentFormat, *((u8 *)saveFileSelect_saveSlots + off + 4));
                gameTextSetColor(0xff, 0xff, 0xff, alpha);
                gameTextAppendStr(*arr, *ptrs);
                off += 0x24;
                arr++;
                ptrs++;
                i++;
            } while (i < 3);
        }
        break;
    }
    gameTextSetColor(0xff, 0xff, 0xff, alpha);
    if (panel->textIdA != 0xffff) {
        if (alpha < 0x7f) {
            gameTextSetColor(0xff, 0xff, 0xff, (u8)(0xff - (alpha << 1)));
            gameTextShow(0x331);
        } else {
            gameTextSetColor(0xff, 0xff, 0xff, (u8)((alpha - 0x7f) << 1));
            gameTextShow(panel->textIdA);
        }
    }
    if (panel->textIdB != 0xffff) {
        gameTextSetColor(0xff, 0xff, 0xff, alpha);
        gameTextShow(panel->textIdB);
    }
    ((void (**)(int))gTitleMenuLinkInterface->vtable)[12](v);
    ((void (**)(int))gTitleMenuLinkInterface->vtable)[4](param);
    gameTextSetDrawFunc(0);
    titleScreenShowCopyright(0);
    lbl_803DD6CE -= 1;
    if (lbl_803DD6CE < 0) {
        lbl_803DD6CE = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: SaveSelectScreen_run
 * EN v1.0 Address: 0x8011AE24
 * EN v1.0 Size: 1328b
 */
#pragma scheduling off
#pragma peephole off
int SaveSelectScreen_run(void)
{
    char buf[32];
    s8 timer;
    int n;
    int sel;
    int slot;
    int prev;
    char *data;
    SaveSelectPanel *panel;
    uint btn;

    timer = lbl_803DD6CF;
    n = framesThisStep;
    if (n > 3) {
        n = 3;
    }
    if (timer > 0) {
        lbl_803DD6CF -= n;
    }
    if (((int (**)(void))gScreenTransitionInterface->vtable)[5]() == 0) {
        ((void (**)(void))gTitleMenuLinkInterface->vtable)[13]();
        lbl_803DD6CE = 4;
    }
    if (lbl_803DD6CD != 0 || lbl_803DD6CC != 0) {
        if ((timer < 13 || lbl_803DD6CF > 12) && lbl_803DD6CF < 1) {
            if (lbl_803DD6CD != 0) {
                n_attractmode_releaseMovieBuffers();
                if (lbl_803DB424 != 0) {
                    trySaveGame(saveFileSelect_currentSlotIndex);
                } else {
                    gplayNewGame(0, -1);
                }
                saveSelectScreenFree(1);
                titleScreenFn_801368d4();
                prev = mmSetFreeDelay(0);
                mapUnload(0x3d, 0x20000000);
                mmSetFreeDelay(prev);
                Music_Trigger(0xbe, 0);
                Music_Trigger(0xc1, 0);
                if (lbl_803DD6C4 != 0) {
                    gplayNewGame(&sFrontendFoxName, saveFileSelect_currentSlotIndex);
                    ((void (**)(int))gMapEventInterface->vtable)[30](1);
                    *((u8 *)((int (**)(void))gMapEventInterface->vtable)[36]() + 0xe) = 0xff;
                }
                if (lbl_803DD6C4 > 1) {
                    sprintf(buf, sSaveGameBinPathFormat);
                    data = loadFileByPath(buf, 0, 0);
                    if (data != NULL) {
                        memcpy(lbl_803DD498, data, 0x6ec);
                    }
                } else {
                    fn_80296B70(0);
                }
                ((void (**)(void))gMapEventInterface->vtable)[8]();
            } else {
                saveSelectScreenFree(0);
                lbl_803DB424 = 0xfe;
                loadUiDll(4);
            }
        }
        return lbl_803DD6CF <= 12;
    }
    if (lbl_803DB9FB == 3) {
        btn = getButtonsJustPressed(0);
        if (btn & 0x100) {
            saveSelectGoToChapterSelect();
        } else if (btn & 0x200) {
            ((void (**)(int, int))gScreenTransitionInterface->vtable)[2](0x14, 5);
            lbl_803DD6CF = 0x23;
            lbl_803DD6CC = 1;
        }
    } else {
        sel = ((int (**)(void))gTitleMenuLinkInterface->vtable)[3]();
        slot = ((int (**)(void))gTitleMenuLinkInterface->vtable)[5]();
        if (slot != lbl_803DD6C0) {
            Sfx_PlayFromObject(0, 0xfc);
        }
        lbl_803DD6C0 = slot;
        if (lbl_803DD6B8 != NULL) {
            ((void (**)(void))gTitleMenuItemInterface->vtable)[5]();
        }
        if (sel != -1 || lbl_803DB9FB == 0) {
            switch (lbl_803DB9FB) {
            case 0:
                saveFileSelect_init(sel, slot);
                break;
            case 1:
                saveSelectOpenFile(sel, slot);
                break;
            case 2:
                if (sel == 0) {
                    Sfx_PlayFromObject(0, 0x419);
                    saveFileSelect_currentSlotIndex = slot;
                    if (lbl_803DB9FB != -1) {
                        ((void (**)(void))gTitleMenuLinkInterface->vtable)[2]();
                    }
                    lbl_803DB9FB = 1;
                    panel = &lbl_8031A7BC[1];
                    panel->entries[0].flags = (u16)(panel->entries[0].flags & ~0x4000);
                    *(s8 *)((char *)panel->entries + 0x56) = 0;
                    *(u16 *)((char *)panel->entries + 0x3c) = 0x3d6;
                    lbl_803DD6C5 = 0;
                    ((void (**)(TitleMenuTextEntry *, u8, int, int, int, int, int, int, int, int, int, int))
                         gTitleMenuLinkInterface->vtable)[1]
                        (panel->entries, panel->count, 0, 0, 5, 4, 0x14, 0xc8, 0xff, 0xff, 0xff, 0xff);
                    ((void (**)(int))gTitleMenuLinkInterface->vtable)[6](0);
                    saveFileSelect_debugCheatProgress = 0;
                    saveFileSelect_saveCheatProgress = 0;
                    saveFileSelect_cheatInputTimer = 0;
                    lbl_803DD6CE = 2;
                } else if (sel == 1) {
                    lbl_803DD6CD = 1;
                    ((void (**)(int, int))gScreenTransitionInterface->vtable)[2](0x14, 5);
                    ((void (**)(int))gTitleMenuControlInterface->vtable)[7](0);
                    ((void (**)(int))gTitleMenuControlInterface->vtable)[7](1);
                    ((void (**)(int))gTitleMenuControlInterface->vtable)[7](2);
                    ((void (**)(int))gTitleMenuControlInterface->vtable)[7](3);
                    lbl_803DD6CF = 0x23;
                }
                break;
            case 4:
                saveSelectSetSlot(sel, slot);
                break;
            }
        }
    }
    if (lbl_803DB9FB == 1) {
        saveFileSelect_checkCheatCodes();
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset
void SaveSelectScreen_initialise(void) {
    int i;
    SaveSelectPanel *panel;

    saveFileSelect_saveSlotsBase = mmAlloc(0x6c, 5, 0);
    lbl_803DD6AC = mmAlloc(0x6c, 5, 0);
    lbl_803DD6C8 = textureLoadAsset(0x2dd);
    gameTextLoadDir(0x15);

    if (lbl_803DD6A0 == 0) {
        lbl_803DD6A0 = gameTextGet(0xec);
    }

    for (i = 0; i < 4; i++) {
        lbl_803A8680[i] = textureLoadAsset((&lbl_803DBA04)[i]);
    }

    if (getUiDllFn_80014930() != 6) {
        if (getUiDllFn_80014930() != 5) {
            ((void (**)(int, int))gScreenTransitionInterface->vtable)[3](0x14, 5);
        }
        saveSelectGoToChooseSlot(1);
    } else {
        saveSelectFn_8011a70c();
        saveFileSelect_saveSlots = saveFileSelect_saveSlotsBase;
        if (lbl_803DB9FB != -1) {
            ((void (**)(void))gTitleMenuLinkInterface->vtable)[2]();
        }

        lbl_803DB9FB = 1;
        panel = &lbl_8031A7BC[1];
        panel->entries[0].flags = (u16)(panel->entries[0].flags & ~0x4000);
        *(s8 *)((char *)panel->entries + 0x56) = 0;
        *(u16 *)((char *)panel->entries + 0x3c) = 0x3d6;
        lbl_803DD6C5 = 0;
        ((void (**)(TitleMenuTextEntry *, u8, int, int, int, int, int, int, int, int, int, int))
             gTitleMenuLinkInterface->vtable)[1]
            (panel->entries, panel->count, 0, 0, 5, 4, 0x14, 0xc8, 0xff, 0xff, 0xff, 0xff);
        ((void (**)(int))gTitleMenuLinkInterface->vtable)[6](0);
        saveFileSelect_debugCheatProgress = 0;
        saveFileSelect_saveCheatProgress = 0;
        saveFileSelect_cheatInputTimer = 0;
    }

    lbl_803DD6CC = 0;
    lbl_803DD6CD = 0;
    lbl_803DD6CF = 0;
    lbl_803DD6CE = 4;
    lbl_803DD6B4 = 0;

    for (i = 0; i < 10; i++) {
        lbl_803A8658[i] = mmAlloc(5, 5, 0);
    }
}

/* Trivial 4b 0-arg blr leaves. */
void SaveSelectScreen_frameEnd_nop(void) {}
