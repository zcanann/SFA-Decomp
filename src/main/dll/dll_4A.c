#include "ghidra_import.h"
#include "main/dll/dll_4A.h"

#define ENTER_SAVE_NAME_CHAR_COUNT 40
#define ENTER_SAVE_NAME_DELETE_INDEX 38
#define ENTER_SAVE_NAME_DONE_INDEX 39
#define ENTER_SAVE_NAME_MAX_LENGTH 3
#define ENTER_SAVE_NAME_MENU_DLL 5
#define ENTER_SAVE_NAME_SFX_CONFIRM 0x418
#define ENTER_SAVE_NAME_SFX_DELETE 0x419
#define ENTER_SAVE_NAME_SFX_TYPE 0x41A

#pragma peephole off
#pragma scheduling off
extern void Sfx_PlayFromObject(u32 obj, u32 sfxId);
extern void set_uiDllIdx_803dc8f0(int idx);
extern void loadUiDll(int index);
extern void buttonDisable(int port, u32 mask);
extern void padClearAnalogInputX(int port);
extern s8 padGetStickX(int port);
extern u32 getButtonsJustPressed(int port);
extern char *gameTextGetStr(u16 textId);
extern void gameTextMeasureString(u8 *str, f32 scale, f32 *outW, f32 *outZero, f32 *outMaxAdv,
                                  f32 *outMaxH, int glyphLang);
extern void gplayNewGame(char *name, s8 slot);

extern u16 lbl_8031A880[];
extern s32 lbl_803A8690[];
extern s32 lbl_803A8730[];
extern s8 saveFileSelect_currentSlotIndex;

extern f32 lbl_803DD6D0;
extern f32 lbl_803DD6D4;
extern u8 lbl_803DD6DA;
extern u32 lbl_803DD6DC;
extern f32 lbl_803DD6E0;
extern s32 lbl_803DD6E4;
extern u32 lbl_803DD6E8;
extern u8 lbl_803DD6EC;
extern u8 lbl_803DD6ED;
extern char lbl_803DD6F0;
extern u8 lbl_803DD6F4;

extern f32 lbl_803E1DB0;
extern f32 lbl_803E1DB4;
extern f32 lbl_803E1DB8;
extern f32 lbl_803E1DBC;
extern f32 lbl_803E1DC0;
extern f32 lbl_803E1DC4;
extern f32 lbl_803E1DC8;
extern f32 lbl_803E1DCC;

/*
 * --INFO--
 *
 * Function: EnterSaveNameScreen_run
 * EN v1.0 Address: 0x8011B868
 * EN v1.0 Size: 1636b
 * EN v1.1 Address: 0x8011BB4C
 * EN v1.1 Size: 1540b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
EnterSaveNameScreen_run(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,undefined4 param_5
                        ,undefined4 param_6,undefined4 param_7,undefined4 param_8)
{
  bool bVar1;
  int iVar2;
  s8 cVar5;
  uint uVar3;
  char *puVar4;
  double dVar7;
  double dVar8;
  
  cVar5 = padGetStickX(0);
  padClearAnalogInputX(0);
  if ((int)cVar5 == 0) {
    if (lbl_803DD6DA == '\0') {
      lbl_803DD6D4 = lbl_803E1DB4;
    }
    else if (lbl_803DD6E4 < 0x14) {
      lbl_803DD6D4 = lbl_803E1DB8;
    }
    else {
      lbl_803DD6D4 = lbl_803E1DBC;
    }
  }
  else {
    lbl_803DD6DA = '\0';
    lbl_803DD6D4 = lbl_803E1DB0 * (f32)(s32)cVar5;
    if (lbl_803DD6D4 * lbl_803DD6D0 < lbl_803E1DB4) {
      lbl_803DD6D4 = lbl_803E1DB4;
    }
  }
  if (lbl_803E1DB4 <= lbl_803DD6D0) {
    if (lbl_803E1DB4 < lbl_803DD6D0) {
      lbl_803DD6E0 = lbl_803DD6E0 + lbl_803DD6D0;
      bVar1 = (f32)(u32)(lbl_803DD6E8 + lbl_803A8730[0] / 2) <= lbl_803DD6E0;
      if (bVar1) {
        lbl_803DD6E0 = lbl_803DD6E0 - (f32)(u32)lbl_803DD6E8;
      }
      param_3 = lbl_803DD6E8;
      if ((lbl_803DD6E4 < ENTER_SAVE_NAME_DONE_INDEX) &&
         (param_3 = lbl_803A8690[lbl_803DD6E4 + 1],
         (f32)(s32)(param_3 + lbl_803A8730[lbl_803DD6E4 + 1] / 2) <= lbl_803DD6E0)) {
        bVar1 = true;
      }
      if (bVar1) {
        if (lbl_803E1DB4 == lbl_803DD6D4) {
          lbl_803DD6D0 = lbl_803E1DB4;
        }
        iVar2 = lbl_803DD6E4 + 1;
        if (ENTER_SAVE_NAME_DONE_INDEX < lbl_803DD6E4 + 1) {
          iVar2 = lbl_803DD6E4 + -ENTER_SAVE_NAME_DONE_INDEX;
        }
        lbl_803DD6E4 = iVar2;
        if ((lbl_803DD6E4 == ENTER_SAVE_NAME_DONE_INDEX) && (lbl_803DD6DA != '\0')) {
          lbl_803DD6DA = '\0';
          lbl_803DD6D4 = lbl_803E1DB4;
          lbl_803DD6D0 = lbl_803E1DB4;
        }
      }
    }
  }
  else {
    lbl_803DD6E0 = lbl_803DD6E0 + lbl_803DD6D0;
    bVar1 = lbl_803DD6E0 <= (f32)(s32)(-lbl_803A8730[ENTER_SAVE_NAME_DONE_INDEX] / 2);
    if (bVar1) {
      lbl_803DD6E0 = lbl_803DD6E0 + (f32)(u32)lbl_803DD6E8;
    }
    if ((0 < lbl_803DD6E4) &&
       (param_3 = lbl_803DD6E4 * 4,
       lbl_803DD6E0 <=
       (f32)(s32)(lbl_803A8690[lbl_803DD6E4] - *(int *)((char *)lbl_803A8730 + param_3) / 2))) {
      bVar1 = true;
    }
    if (bVar1) {
      if (lbl_803E1DB4 == lbl_803DD6D4) {
        lbl_803DD6D0 = lbl_803E1DB4;
      }
      iVar2 = lbl_803DD6E4 + -1;
      if (lbl_803DD6E4 + -1 < 0) {
        iVar2 = lbl_803DD6E4 + ENTER_SAVE_NAME_DONE_INDEX;
      }
      lbl_803DD6E4 = iVar2;
      if ((lbl_803DD6E4 == ENTER_SAVE_NAME_DONE_INDEX) && (lbl_803DD6DA != '\0')) {
        lbl_803DD6D4 = lbl_803E1DB4;
        lbl_803DD6D0 = lbl_803E1DB4;
        lbl_803DD6DA = '\0';
      }
    }
  }
  dVar7 = (double)lbl_803DD6E0;
  lbl_803DD6DC = lbl_803DD6E8;
  if ((f64)(f32)(u32)(lbl_803DD6E8 >> 2) <= dVar7) {
    lbl_803DD6DC = 0;
  }
  dVar8 = (double)lbl_803DD6D0;
  if (((double)lbl_803E1DB4 != dVar8) || ((double)lbl_803E1DB4 != (double)lbl_803DD6D4)) {
    if ((dVar8 < (double)lbl_803E1DB4) || ((double)lbl_803DD6D4 < (double)lbl_803E1DB4)) {
      if (dVar8 <= (double)lbl_803E1DC0) {
        dVar7 = (double)lbl_803E1DC4;
        lbl_803DD6D0 =
             (float)(dVar7 * (double)(float)((double)lbl_803DD6D4 - dVar8) +
                    (double)lbl_803DD6D0);
      }
      else {
        lbl_803DD6D0 = lbl_803E1DC0;
      }
    }
    else if ((double)lbl_803E1DC8 <= dVar8) {
      dVar7 = (double)lbl_803E1DC4;
      lbl_803DD6D0 =
           (float)(dVar7 * (double)(float)((double)lbl_803DD6D4 - dVar8) + (double)lbl_803DD6D0)
      ;
    }
    else {
      lbl_803DD6D0 = lbl_803E1DC8;
    }
  }
  if ((cVar5 == '\0') && (lbl_803E1DB4 == lbl_803DD6D0)) {
    uVar3 = getButtonsJustPressed(0);
    buttonDisable(0,uVar3);
    if ((uVar3 & 0x100) == 0) {
      if ((uVar3 & 0x200) != 0) {
        lbl_803DD6DA = '\0';
        Sfx_PlayFromObject(0,ENTER_SAVE_NAME_SFX_DELETE);
        if (lbl_803DD6F4 == 0) {
          loadUiDll(ENTER_SAVE_NAME_MENU_DLL);
          set_uiDllIdx_803dc8f0(ENTER_SAVE_NAME_MENU_DLL);
        }
        else {
          lbl_803DD6F4 = lbl_803DD6F4 - 1;
          (&lbl_803DD6F0)[lbl_803DD6F4] = 0;
          lbl_803DD6EC = 2;
        }
      }
    }
    else if ((lbl_803DD6E4 < ENTER_SAVE_NAME_DELETE_INDEX) && (lbl_803DD6F4 < ENTER_SAVE_NAME_MAX_LENGTH)) {
      puVar4 = gameTextGetStr(lbl_8031A880[lbl_803DD6E4]);
      uVar3 = (uint)lbl_803DD6F4;
      lbl_803DD6F4 = lbl_803DD6F4 + 1;
      (&lbl_803DD6F0)[uVar3] = *puVar4;
      (&lbl_803DD6F0)[lbl_803DD6F4] = 0;
      lbl_803DD6EC = 2;
      Sfx_PlayFromObject(0,ENTER_SAVE_NAME_SFX_TYPE);
      if (lbl_803DD6F4 == ENTER_SAVE_NAME_MAX_LENGTH) {
        lbl_803DD6DA = '\x01';
      }
    }
    else if ((lbl_803DD6E4 == ENTER_SAVE_NAME_DELETE_INDEX) && (lbl_803DD6F4 != 0)) {
      Sfx_PlayFromObject(0,ENTER_SAVE_NAME_SFX_DELETE);
      lbl_803DD6F4 = lbl_803DD6F4 - 1;
      (&lbl_803DD6F0)[lbl_803DD6F4] = 0;
      lbl_803DD6EC = 2;
      lbl_803DD6DA = '\0';
    }
    else if (lbl_803DD6E4 == ENTER_SAVE_NAME_DONE_INDEX) {
      if (lbl_803DD6F4 == 0) {
        lbl_803DD6F0 = 0x46;
        (&lbl_803DD6F0)[1] = 0x4f;
        (&lbl_803DD6F0)[2] = 0x58;
        (&lbl_803DD6F0)[3] = 0;
      }
      Sfx_PlayFromObject(0,ENTER_SAVE_NAME_SFX_CONFIRM);
      gplayNewGame(&lbl_803DD6F0,saveFileSelect_currentSlotIndex);
      loadUiDll(ENTER_SAVE_NAME_MENU_DLL);
      lbl_803DD6EC = 2;
    }
  }
  return 0;
}

extern int *gTitleMenuLinkInterface;
void EnterSaveNameScreen_release(void) {
    ((void (*)(void))((void**)*gTitleMenuLinkInterface)[2])();
}

void EnterSaveNameScreen_initialise(void) {
    int i;
    f32 width;

    lbl_803DD6EC = 2;
    lbl_803DD6ED = 2;
    lbl_803DD6F4 = 0;
    lbl_803DD6F0 = 0;
    lbl_803DD6E8 = 0;

    for (i = 0; i < ENTER_SAVE_NAME_CHAR_COUNT; i++) {
        gameTextMeasureString((u8 *)gameTextGetStr(lbl_8031A880[i]), lbl_803E1DCC, &width, NULL,
                              NULL, NULL, -1);
        lbl_803A8730[i] = (s32)width;
        lbl_803A8690[i] = lbl_803DD6E8;
        lbl_803DD6E8 += lbl_803A8730[i];
    }

    lbl_803DD6E4 = 0;
    lbl_803DD6E0 = (f32)(lbl_803A8730[0] / 2);
    lbl_803DD6DC = lbl_803DD6E8;
    lbl_803DD6DA = 0;
    Sfx_PlayFromObject(0, ENTER_SAVE_NAME_SFX_CONFIRM);
}
