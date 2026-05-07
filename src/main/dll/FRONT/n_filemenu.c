#include "ghidra_import.h"
#include "main/dll/FRONT/n_filemenu.h"

typedef struct TitleMenuTextEntry {
  u8 pad0[0x16];
  u16 flags;
  u8 pad18[0x24];
} TitleMenuTextEntry;

typedef struct TitleMenuControl {
  void *vtable;
} TitleMenuControl;

extern void FUN_80006824(uint obj, ushort sfxId);
extern void FUN_80006b84(int id);
extern void FUN_80006ba8(int controller, uint buttons);
extern void FUN_80006bac(int controller);
extern void FUN_80006bb0(int controller);
extern void FUN_80006bb4(int controller, u8 *dpad, u8 *face);
extern uint FUN_80006c00(int controller);
extern void loadUiDll(int id);
extern void fn_8001FEE4(void);
extern uint mmSetFreeDelay(uint delay);
extern void mapUnload(int mapId, uint flags);
extern void fn_8005CDD4(int arg);
extern void fn_8005CDF8(int arg);
extern void fn_8005CEA8(int arg);
extern void fn_8007DD04(u8 retry);
extern void loadSaveSettings(void);
extern int titleLoadSaveFiles(void);
extern void gameplay_capturePreviewSettings(void);
extern float fn_801115E4(void);
extern void n_attractmode_releaseMovieBuffers(void);
extern void n_attractmode_prepareMovie(void);
extern void fn_80117B68(int fade, int frames);
extern void fn_80130464(u8 v);
extern void fn_8013046C(void);
extern u8 fn_80134BBC(void);
extern void fn_801368A4(u8 arg);
extern void fn_801368C4(u8 arg);
extern void fn_801368D4(void);
extern void fn_8007D960(int);

extern u8 framesThisStep;
extern u8 lbl_803DB424;
extern TitleMenuTextEntry lbl_8031A214[4];
extern s32 lbl_803DD610;
extern u8 lbl_803DD614;
extern u8 lbl_803DD615;
extern u8 lbl_803DD616;
extern s8 lbl_803DD617;
extern u8 lbl_803DD618;
extern u8 lbl_803DD619;
extern u8 lbl_803DD61A;
extern s32 lbl_803DD648;
extern u8 lbl_803DD64C;
extern u8 lbl_803DD64D;
extern u8 lbl_803DD64E;
extern u8 lbl_803DD64F;
extern u8 lbl_803DD650;
extern u8 lbl_803DD651;
extern u8 lbl_803DD652;
extern u8 lbl_803DD680;
extern s32 lbl_803DD698;
extern u8 lbl_803DD6F8;
extern TitleMenuControl *lbl_803DCA50;
extern TitleMenuControl *lbl_803DCAA0;
extern f64 lbl_803E1D28;

static int TitleMenu_GetMenuId(void)
{
  return (*(int (*)(void))((int)lbl_803DCA50->vtable + 0x10))();
}

static void TitleMenu_SetMenuState(int state, int arg)
{
  (*(void (*)(int, int))((int)lbl_803DCA50->vtable + 0x60))(state,arg);
}

static int TitleMenu_GetFadeState(void)
{
  return (*(int (*)(void))((int)lbl_803DCAA0->vtable + 0xc))();
}

static u8 TitleMenu_GetSelection(void)
{
  return (*(u8 (*)(void))((int)lbl_803DCAA0->vtable + 0x14))();
}

static void TitleMenu_BindEntries(void)
{
  (*(void (*)(TitleMenuTextEntry *))((int)lbl_803DCAA0->vtable + 0x2c))(lbl_8031A214);
}

static void TitleMenu_ClearPanel(void)
{
  (*(void (*)(void))((int)lbl_803DCAA0->vtable + 8))();
}

static void TitleMenu_OpenPanel(void)
{
  (*(void (*)(TitleMenuTextEntry *, int, int, int, int, int, int, int, int, int, int, int))
      ((int)lbl_803DCAA0->vtable + 4))(lbl_8031A214,9,5,0,0,0,0x14,200,0xff,0xff,0xff,0xff);
}

static void TitleMenu_SetPanelSelection(int selection)
{
  (*(void (*)(int))((int)lbl_803DCAA0->vtable + 0x18))(selection);
}

static void TitleMenu_SetEntryHighlight(int entry)
{
  int i;

  for (i = 0; i < 4; i++) {
    if (i == entry) {
      lbl_8031A214[i].flags &= 0xbfff;
    } else {
      lbl_8031A214[i].flags |= 0x4000;
    }
  }
  TitleMenu_BindEntries();
}

static void TitleMenu_ReloadSaveSettings(void)
{
  int result;

  result = titleLoadSaveFiles();
  if ((result == 0) && (lbl_803DB424 != 0)) {
    fn_8007DD04(1);
  }
  loadSaveSettings();
}

/*
 * --INFO--
 *
 * Function: fn_801166C8
 * EN v1.0 Address: 0x801166C8
 * EN v1.0 Size: 2124b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int fn_801166C8(void)
{
  bool inputPressed;
  int menuId;
  uint buttons;
  u8 previousFadeTimer;
  u8 frames;
  u8 dpad[11];
  u8 face;

  previousFadeTimer = lbl_803DD651;
  frames = framesThisStep;
  if (lbl_803DB424 == 0xfe) {
    TitleMenu_ReloadSaveSettings();
    if (lbl_803DB424 == 0xfe) {
      lbl_803DB424 = 1;
    }
  }
  if ((lbl_803DD61A == 0) && (lbl_803DD648 == 0)) {
    n_attractmode_releaseMovieBuffers();
    loadUiDll(1);
    fn_8001FEE4();
    fn_801368D4();
    buttons = mmSetFreeDelay(0);
    mapUnload(0x3d,0x20000000);
    mmSetFreeDelay(buttons);
    gameplay_capturePreviewSettings();
    return 0;
  }

  fn_8005CEA8(0);
  fn_8005CDF8(0);
  if (fn_80134BBC() != 0) {
    return 0;
  }

  if (lbl_803DD648 != 0) {
    lbl_803DD648--;
  }
  if (lbl_803DD619 != 0) {
    n_attractmode_prepareMovie();
  }
  if ((lbl_803DD64D != 0) && (--lbl_803DD64D == 0) && (lbl_803DD64F != 0)) {
    fn_80117B68(100,1000);
  }
  if ((lbl_803DD610 == 2) && (++lbl_803DD698 > 10)) {
    n_attractmode_releaseMovieBuffers();
  }
  if (((lbl_803DD610 == 2) && (lbl_803DD64F != 0)) && (lbl_803DD64E != 0)) {
    buttons = FUN_80006c00(0);
    FUN_80006bb4(0,dpad,&face);
    FUN_80006ba8(0,buttons);
    FUN_80006bb0(0);
    FUN_80006bac(0);

    inputPressed = false;
    if ((lbl_803DD680 == 0) || (lbl_803DD648 != 0)) {
      if ((buttons != 0) || ((dpad[0] != 0 || (face != 0)))) {
        inputPressed = true;
      }
    } else {
      inputPressed = true;
    }
    if (lbl_803DD680 != 0) {
      lbl_803DD680 = 0;
    }
    if (inputPressed) {
      if (((buttons == 0) && (dpad[0] == 0)) && (face == 0)) {
        lbl_803DD64C = 1;
        lbl_803DD648 = 0x3c;
      } else {
        lbl_803DD64C = 2;
      }
      TitleMenu_SetPanelSelection(0);
      lbl_803DD64F = 0;
      TitleMenu_SetMenuState(0,1);
      if (lbl_803DB424 == 0xff) {
        TitleMenu_ReloadSaveSettings();
        if (lbl_803DB424 == 0xff) {
          lbl_803DB424 = 1;
        }
      }
    }
  } else if ((lbl_803DD64E != 0) && (lbl_803DD64F == 0)) {
    buttons = FUN_80006c00(0);
    FUN_80006bb4(0,dpad,&face);
    if ((buttons == 0) && ((dpad[0] == 0 && (face == 0)))) {
      if ((lbl_803DD680 != 0) && (lbl_803DD680 = 0, lbl_803DD648 == 0)) {
        lbl_803DD648 = 0x3c;
        lbl_803DD64C--;
        if (lbl_803DD64C == 0) {
          lbl_803DD64C = 1;
          TitleMenu_SetMenuState(4,1);
          lbl_803DD64F = 1;
          lbl_803DD617 = -0x19;
        }
      }
    } else {
      lbl_803DD64C = 2;
    }
  }

  if (frames > 3) {
    frames = 3;
  }
  if (lbl_803DD651 > 0) {
    lbl_803DD651 -= frames;
  }
  menuId = TitleMenu_GetMenuId();
  if (menuId != 0x57) {
    lbl_803DD64E = 0;
    return 0;
  }

  lbl_803DD64E = 1;
  if (lbl_803DD650 == 0) {
    menuId = TitleMenu_GetFadeState();
    lbl_803DD614 = TitleMenu_GetSelection();
    if ((((double)lbl_803E1D28 == (double)fn_801115E4()) && (lbl_803DD616 < 0xff)) &&
        (lbl_803DD64F == 0)) {
      lbl_803DD617 = 0x19;
      if (lbl_803DD614 == 0) {
        lbl_803DD618 = 1;
      } else {
        lbl_803DD618 = 0;
      }
    } else if (lbl_803DD615 != lbl_803DD614) {
      TitleMenu_SetMenuState(lbl_803DD614,1);
      FUN_80006824(0,0x37b);
      lbl_803DD617 = -0x19;
      lbl_803DD615 = lbl_803DD614;
      fn_80130464(0);
    }
    if ((int)((uint)lbl_803DD616 + (int)lbl_803DD617) < 0xff) {
      if ((int)((uint)lbl_803DD616 + (int)lbl_803DD617) < 1) {
        TitleMenu_SetEntryHighlight(lbl_803DD614);
        lbl_803DD616 = 0;
        lbl_803DD617 = 0;
        if (lbl_803DD614 != 0) {
          lbl_803DD618 = 0;
        }
      } else {
        lbl_803DD616 += lbl_803DD617;
      }
    } else {
      lbl_803DD616 = 0xff;
      lbl_803DD617 = 0;
      fn_80130464(1);
    }
    if (lbl_803DD652 == 0) {
      if (menuId == 1) {
        TitleMenu_ClearPanel();
        TitleMenu_OpenPanel();
        lbl_803DD652 = 1;
      }
    } else {
      fn_801368C4(lbl_803DD614);
      if ((menuId == 1) && (lbl_803DD616 == 0xff)) {
        fn_801368A4(1);
        lbl_803DD651 = 1;
        fn_80130464(1);
        FUN_80006824(0,0xff);
        if (lbl_803DD614 == 2) {
          lbl_803DD650 = 7;
          lbl_803DD6F8 = 1;
        } else if (lbl_803DD614 < 2) {
          if (lbl_803DD614 == 0) {
            lbl_803DD650 = 5;
          } else {
            lbl_803DD650 = 7;
            lbl_803DD6F8 = 0;
          }
        } else if (lbl_803DD614 < 4) {
          lbl_803DD650 = 7;
          lbl_803DD6F8 = 2;
        }
        return 0;
      }
      fn_801368A4(0);
    }
    return 0;
  }

  if (((previousFadeTimer < 0xd) || (lbl_803DD651 > 0xc)) && (lbl_803DD651 < 1)) {
    TitleMenu_ClearPanel();
    fn_8005CDD4(0);
    fn_8013046C();
    loadUiDll(lbl_803DD650);
  }
  return (uint)((uint)(int)lbl_803DD651 < 0xd) - ((int)lbl_803DD651 >> 0x1f);
}

#pragma scheduling off
#pragma peephole off
void TitleMenu_release(void)
{
  fn_8013046C();
  fn_80130464(1);
  fn_8007D960(1);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80116F44(int a)
{
  u8 v = (u8)a;
  lbl_803DD614 = v;
  lbl_803DD615 = 0xff;
  (*(void (*)(int))((int)lbl_803DCAA0->vtable + 0x18))(v);
}
#pragma peephole reset
#pragma scheduling reset
