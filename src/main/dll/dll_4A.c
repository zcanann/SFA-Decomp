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
extern int getButtonsJustPressed(int port);
extern char *gameTextGetStr(u16 textId);
extern void gameTextMeasureString(u8 *str, f32 scale, f32 *outW, f32 *outZero, f32 *outMaxAdv,
                                  f32 *outMaxH, int glyphLang);
extern void gplayNewGame(char *name, u8 slot);

extern u16 lbl_8031A880[];
extern s32 lbl_803A8690[];
extern s32 lbl_803A8730[];
extern u8 saveFileSelect_currentSlotIndex;

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
  s8 stickX;
  int buttons;
  u8 moved;

  stickX = padGetStickX(0);
  padClearAnalogInputX(0);
  if (stickX != 0) {
    lbl_803DD6DA = 0;
    lbl_803DD6D4 = 0.08f * (f32)stickX;
    if (lbl_803DD6D4 * lbl_803DD6D0 < 0.0f) {
      lbl_803DD6D4 = 0.0f;
    }
  }
  else {
    if (lbl_803DD6DA != 0) {
      if (lbl_803DD6E4 < 0x14) {
        lbl_803DD6D4 = -10.0f;
      }
      else {
        lbl_803DD6D4 = 10.0f;
      }
    }
    else {
      lbl_803DD6D4 = 0.0f;
    }
  }
  moved = 0;
  if (lbl_803DD6D0 < 0.0f) {
    lbl_803DD6E0 = lbl_803DD6E0 + lbl_803DD6D0;
    if (lbl_803DD6E0 <= (f32)(-lbl_803A8730[ENTER_SAVE_NAME_DONE_INDEX] / 2)) {
      lbl_803DD6E0 = lbl_803DD6E0 + (f32)lbl_803DD6E8;
      moved = 1;
    }
    if ((0 < lbl_803DD6E4) &&
        (lbl_803DD6E0 <= (f32)(lbl_803A8690[lbl_803DD6E4] - lbl_803A8730[lbl_803DD6E4 - 1] / 2))) {
      moved = 1;
    }
    if (moved != 0) {
      if (0.0f == lbl_803DD6D4) {
        lbl_803DD6D0 = 0.0f;
      }
      lbl_803DD6E4 = lbl_803DD6E4 - 1;
      if (lbl_803DD6E4 < 0) {
        lbl_803DD6E4 = lbl_803DD6E4 + ENTER_SAVE_NAME_CHAR_COUNT;
      }
      if ((lbl_803DD6E4 == ENTER_SAVE_NAME_DONE_INDEX) && (lbl_803DD6DA != 0)) {
        lbl_803DD6D4 = 0.0f;
        lbl_803DD6D0 = 0.0f;
        lbl_803DD6DA = 0;
      }
    }
  }
  else if (lbl_803DD6D0 > 0.0f) {
    lbl_803DD6E0 = lbl_803DD6E0 + lbl_803DD6D0;
    if (lbl_803DD6E0 >= (f32)(lbl_803DD6E8 + lbl_803A8730[0] / 2)) {
      lbl_803DD6E0 = lbl_803DD6E0 - (f32)lbl_803DD6E8;
      moved = 1;
    }
    if ((lbl_803DD6E4 < ENTER_SAVE_NAME_DONE_INDEX) &&
        (lbl_803DD6E0 >= (f32)(lbl_803A8690[lbl_803DD6E4 + 1] + lbl_803A8730[lbl_803DD6E4 + 1] / 2))) {
      moved = 1;
    }
    if (moved != 0) {
      if (0.0f == lbl_803DD6D4) {
        lbl_803DD6D0 = 0.0f;
      }
      lbl_803DD6E4 = lbl_803DD6E4 + 1;
      if (lbl_803DD6E4 >= ENTER_SAVE_NAME_CHAR_COUNT) {
        lbl_803DD6E4 = lbl_803DD6E4 - ENTER_SAVE_NAME_CHAR_COUNT;
      }
      if ((lbl_803DD6E4 == ENTER_SAVE_NAME_DONE_INDEX) && (lbl_803DD6DA != 0)) {
        lbl_803DD6DA = 0;
        lbl_803DD6D4 = 0.0f;
        lbl_803DD6D0 = 0.0f;
      }
    }
  }
  lbl_803DD6DC = (lbl_803DD6E0 < (f32)(lbl_803DD6E8 >> 2)) ? lbl_803DD6E8 : 0;
  if ((0.0f != lbl_803DD6D0) || (0.0f != lbl_803DD6D4)) {
    if ((lbl_803DD6D0 < 0.0f) || (lbl_803DD6D4 < 0.0f)) {
      if (lbl_803DD6D0 > -1.2f) {
        lbl_803DD6D0 = -1.2f;
      }
      else {
        lbl_803DD6D0 = 0.025f * (lbl_803DD6D4 - lbl_803DD6D0) + lbl_803DD6D0;
      }
    }
    else if (lbl_803DD6D0 < 1.2f) {
      lbl_803DD6D0 = 1.2f;
    }
    else {
      lbl_803DD6D0 = 0.025f * (lbl_803DD6D4 - lbl_803DD6D0) + lbl_803DD6D0;
    }
  }
  if ((stickX == 0) && (0.0f == lbl_803DD6D0)) {
    buttons = getButtonsJustPressed(0);
    buttonDisable(0,buttons);
    if (buttons & 0x100) {
      if ((lbl_803DD6E4 <= 0x25) && (lbl_803DD6F4 < ENTER_SAVE_NAME_MAX_LENGTH)) {
        (&lbl_803DD6F0)[lbl_803DD6F4++] = *gameTextGetStr(lbl_8031A880[lbl_803DD6E4]);
        (&lbl_803DD6F0)[lbl_803DD6F4] = 0;
        lbl_803DD6EC = 2;
        Sfx_PlayFromObject(0,ENTER_SAVE_NAME_SFX_TYPE);
        if (lbl_803DD6F4 == ENTER_SAVE_NAME_MAX_LENGTH) {
          lbl_803DD6DA = 1;
        }
      }
      else if ((lbl_803DD6E4 == ENTER_SAVE_NAME_DELETE_INDEX) && (lbl_803DD6F4 != 0)) {
        Sfx_PlayFromObject(0,ENTER_SAVE_NAME_SFX_DELETE);
        lbl_803DD6F4 -= 1;
        (&lbl_803DD6F0)[lbl_803DD6F4] = 0;
        lbl_803DD6EC = 2;
        lbl_803DD6DA = 0;
      }
      else if (lbl_803DD6E4 == ENTER_SAVE_NAME_DONE_INDEX) {
        if (lbl_803DD6F4 == 0) {
          lbl_803DD6F0 = 'F';
          (&lbl_803DD6F0)[1] = 'O';
          (&lbl_803DD6F0)[2] = 'X';
          (&lbl_803DD6F0)[3] = 0;
        }
        Sfx_PlayFromObject(0,ENTER_SAVE_NAME_SFX_CONFIRM);
        gplayNewGame(&lbl_803DD6F0,saveFileSelect_currentSlotIndex);
        loadUiDll(ENTER_SAVE_NAME_MENU_DLL);
        lbl_803DD6EC = 2;
      }
    }
    else if (buttons & 0x200) {
      lbl_803DD6DA = 0;
      Sfx_PlayFromObject(0,ENTER_SAVE_NAME_SFX_DELETE);
      if (lbl_803DD6F4 != 0) {
        lbl_803DD6F4 -= 1;
        (&lbl_803DD6F0)[lbl_803DD6F4] = 0;
        lbl_803DD6EC = 2;
      }
      else {
        loadUiDll(ENTER_SAVE_NAME_MENU_DLL);
        set_uiDllIdx_803dc8f0(ENTER_SAVE_NAME_MENU_DLL);
      }
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
        gameTextMeasureString((u8 *)gameTextGetStr(lbl_8031A880[i]), 1.0f, &width, NULL,
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
