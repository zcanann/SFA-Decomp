#include "ghidra_import.h"
#include "main/dll/FRONT/n_filemenu.h"
#include "main/dll/FRONT/dll_39.h"

extern void Sfx_PlayFromObject(uint obj, ushort sfxId);
extern void buttonDisable(int controller, uint buttons);
extern void padClearAnalogInputY(int controller);
extern void padClearAnalogInputX(int controller);
extern void padGetAnalogInput(int controller, s8 *dpad, s8 *face);
extern uint getButtonsJustPressed(int controller);
extern void loadUiDll(int id);
extern void doNothing_onSaveSelectScreenExit(void);
extern uint mmSetFreeDelay(uint delay);
extern void mapUnload(int mapId, uint flags);
extern void titleScreenFn_8005cdd4(int arg);
extern void setDrawLights(int arg);
extern void setIsOvercast(int arg);
extern void memCardFn_8007dd04(u8 retry);
extern void loadSaveSettings(void);
extern int saveFn_800e8508(void);
extern void titleDoLoadSave(void);
extern float titleScreenGetCamProgress(void);
extern void Movie_SetVolumeFade(int volume, int fadeFrames);
extern void titleScreenFn_80130464(u8 v);
extern void setLinkNotRotated(void);
extern u8 shouldShowCredits(void);
extern void titleScreenFn_801368a4(u8 arg);
extern void titleScreenFn_801368c4(u8 arg);
extern void titleScreenFn_801368d4(void);
extern void saveFn_8007d960(int);

extern u8 framesThisStep;
extern u8 lbl_803DB424;
extern TitleMenuTextEntry lbl_8031A214[4];
extern s32 lbl_803DD610;
extern u8 lbl_803DD614;
extern u8 gTitleMenuPreviousSelection;
extern u8 gTitleMenuSelectionFade;
extern s8 gTitleMenuSelectionFadeStep;
extern u8 lbl_803DD618;
extern u8 lbl_803DD619;
extern u8 gAttractMovieAutoplayEnabled;
extern s32 gTitleMenuInputCooldown;
extern u8 gAttractMovieReplayCountdown;
extern u8 lbl_803DD64D;
extern u8 gTitleMenuReadyForInput;
extern u8 lbl_803DD64F;
extern u8 gTitleMenuNextDllId;
extern u8 gTitleMenuLoadDelay;
extern u8 gTitleMenuPanelOpen;
extern u8 gAttractMovieLoopCompleted;
extern s32 lbl_803DD698;
extern u8 lbl_803DD6F8;
extern TitleMenuControl *gCameraInterface;
extern TitleMenuControl *gTitleMenuLinkInterface;
extern f64 lbl_803E1D28;

#define TitleMenu_GetMenuId() (*(int (**)(void))((int)gCameraInterface->vtable + 0x10))()
#define TitleMenu_SetMenuState(state, arg) (*(void (**)(int, int))((int)gCameraInterface->vtable + 0x60))(state,arg)
#define TitleMenu_GetFadeState() (*(int (**)(void))((int)gTitleMenuLinkInterface->vtable + 0xc))()
#define TitleMenu_GetSelection() (*(u8 (**)(void))((int)gTitleMenuLinkInterface->vtable + 0x14))()
#define TitleMenu_BindEntries() (*(void (**)(TitleMenuTextEntry *))((int)gTitleMenuLinkInterface->vtable + 0x2c))(lbl_8031A214)
#define TitleMenu_ClearPanel() (*(void (**)(void))((int)gTitleMenuLinkInterface->vtable + 8))()
#define TitleMenu_OpenPanel() (*(void (**)(TitleMenuTextEntry *, int, int, int, int, int, int, int, int, int, int, int))((int)gTitleMenuLinkInterface->vtable + 4))(lbl_8031A214,9,5,0,0,0,0x14,200,0xff,0xff,0xff,0xff)
#define TitleMenu_SetPanelSelection(selection) (*(void (**)(int))((int)gTitleMenuLinkInterface->vtable + 0x18))(selection)
#define TitleMenu_SetEntryHighlight(entry) \
  do { \
    int i; \
    for (i = 0; i < 4; i++) { \
      if (i == (entry)) { \
        lbl_8031A214[i].flags &= 0xbfff; \
      } else { \
        lbl_8031A214[i].flags |= 0x4000; \
      } \
    } \
    TitleMenu_BindEntries(); \
  } while (0)
#define TitleMenu_ReloadSaveSettings() \
  do { \
    int result; \
    result = saveFn_800e8508(); \
    if ((result == 0) && (lbl_803DB424 != 0)) { \
      memCardFn_8007dd04(1); \
    } \
    loadSaveSettings(); \
  } while (0)

/*
 * --INFO--
 *
 * Function: TitleMenu_run
 * EN v1.0 Address: 0x801166C8
 * EN v1.0 Size: 2124b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int TitleMenu_run(void)
{
  bool inputPressed;
  int menuId;
  uint buttons;
  u8 previousFadeTimer;
  u8 frames;
  s8 dpad;
  s8 face;

  previousFadeTimer = gTitleMenuLoadDelay;
  frames = framesThisStep;
  if (lbl_803DB424 == 0xfe) {
    TitleMenu_ReloadSaveSettings();
    if (lbl_803DB424 == 0xfe) {
      lbl_803DB424 = 1;
    }
  }
  if ((gAttractMovieAutoplayEnabled == 0) && (gTitleMenuInputCooldown == 0)) {
    n_attractmode_releaseMovieBuffers();
    loadUiDll(1);
    doNothing_onSaveSelectScreenExit();
    titleScreenFn_801368d4();
    buttons = mmSetFreeDelay(0);
    mapUnload(0x3d,0x20000000);
    mmSetFreeDelay(buttons);
    titleDoLoadSave();
    return 0;
  }

  setIsOvercast(0);
  setDrawLights(0);
  if (shouldShowCredits() != 0) {
    return 0;
  }

  if (gTitleMenuInputCooldown != 0) {
    gTitleMenuInputCooldown--;
  }
  if (gAttractMoviePreparePending != 0) {
    n_attractmode_prepareMovie();
  }
  if ((gAttractMovieRetraceCountdown != 0) && (--gAttractMovieRetraceCountdown == 0) &&
      (gAttractMoviePlaybackEnabled != 0)) {
    Movie_SetVolumeFade(100,1000);
  }
  if ((gAttractMovieState == NATTRACTMODE_MOVIE_STATE_PREPARED) &&
      (++gAttractMovieIdleFrameCount > NATTRACTMODE_MOVIE_RETRACE_COUNTDOWN)) {
    n_attractmode_releaseMovieBuffers();
  }
  if (((gAttractMovieState == NATTRACTMODE_MOVIE_STATE_PREPARED) &&
       (gAttractMoviePlaybackEnabled != 0)) &&
      (gTitleMenuReadyForInput != 0)) {
    buttons = getButtonsJustPressed(0);
    padGetAnalogInput(0,&dpad,&face);
    buttonDisable(0,buttons);
    padClearAnalogInputX(0);
    padClearAnalogInputY(0);

    inputPressed = false;
    if ((gAttractMovieLoopCompleted == 0) || (gTitleMenuInputCooldown != 0)) {
      if ((buttons != 0) || ((dpad != 0 || (face != 0)))) {
        inputPressed = true;
      }
    } else {
      inputPressed = true;
    }
    if (gAttractMovieLoopCompleted != 0) {
      gAttractMovieLoopCompleted = 0;
    }
    if (inputPressed) {
      if (((buttons == 0) && (dpad == 0)) && (face == 0)) {
        gAttractMovieReplayCountdown = 1;
        gTitleMenuInputCooldown = 0x3c;
      } else {
        gAttractMovieReplayCountdown = 2;
      }
      TitleMenu_SetPanelSelection(0);
      gAttractMoviePlaybackEnabled = 0;
      TitleMenu_SetMenuState(0,1);
      if (lbl_803DB424 == 0xff) {
        TitleMenu_ReloadSaveSettings();
        if (lbl_803DB424 == 0xff) {
          lbl_803DB424 = 1;
        }
      }
    }
  } else if ((gTitleMenuReadyForInput != 0) && (gAttractMoviePlaybackEnabled == 0)) {
    buttons = getButtonsJustPressed(0);
    padGetAnalogInput(0,&dpad,&face);
    if ((buttons == 0) && ((dpad == 0 && (face == 0)))) {
      if ((gAttractMovieLoopCompleted != 0) && (gAttractMovieLoopCompleted = 0, gTitleMenuInputCooldown == 0)) {
        gTitleMenuInputCooldown = 0x3c;
        gAttractMovieReplayCountdown--;
        if (gAttractMovieReplayCountdown == 0) {
          gAttractMovieReplayCountdown = 1;
          TitleMenu_SetMenuState(4,1);
          gAttractMoviePlaybackEnabled = 1;
          gTitleMenuSelectionFadeStep = -0x19;
        }
      }
    } else {
      gAttractMovieReplayCountdown = 2;
    }
  }

  if (frames > 3) {
    frames = 3;
  }
  if (gTitleMenuLoadDelay > 0) {
    gTitleMenuLoadDelay -= frames;
  }
  menuId = TitleMenu_GetMenuId();
  if (menuId != 0x57) {
    gTitleMenuReadyForInput = 0;
    return 0;
  }

  gTitleMenuReadyForInput = 1;
  if (gTitleMenuNextDllId == 0) {
    menuId = TitleMenu_GetFadeState();
    gTitleMenuSelection = TitleMenu_GetSelection();
    if ((((double)lbl_803E1D28 == (double)titleScreenGetCamProgress()) && (gTitleMenuSelectionFade < 0xff)) &&
        (gAttractMoviePlaybackEnabled == 0)) {
      gTitleMenuSelectionFadeStep = 0x19;
      if (gTitleMenuSelection == 0) {
        lbl_803DD618 = 1;
      } else {
        lbl_803DD618 = 0;
      }
    } else if (gTitleMenuPreviousSelection != gTitleMenuSelection) {
      TitleMenu_SetMenuState(gTitleMenuSelection,1);
      Sfx_PlayFromObject(0,0x37b);
      gTitleMenuSelectionFadeStep = -0x19;
      gTitleMenuPreviousSelection = gTitleMenuSelection;
      titleScreenFn_80130464(0);
    }
    if ((int)((uint)gTitleMenuSelectionFade + (int)gTitleMenuSelectionFadeStep) < 0xff) {
      if ((int)((uint)gTitleMenuSelectionFade + (int)gTitleMenuSelectionFadeStep) < 1) {
        TitleMenu_SetEntryHighlight(gTitleMenuSelection);
        gTitleMenuSelectionFade = 0;
        gTitleMenuSelectionFadeStep = 0;
        if (gTitleMenuSelection != 0) {
          lbl_803DD618 = 0;
        }
      } else {
        gTitleMenuSelectionFade += gTitleMenuSelectionFadeStep;
      }
    } else {
      gTitleMenuSelectionFade = 0xff;
      gTitleMenuSelectionFadeStep = 0;
      titleScreenFn_80130464(1);
    }
    if (gTitleMenuPanelOpen == 0) {
      if (menuId == 1) {
        TitleMenu_ClearPanel();
        TitleMenu_OpenPanel();
        gTitleMenuPanelOpen = 1;
      }
    } else {
      titleScreenFn_801368c4(gTitleMenuSelection);
      if ((menuId == 1) && (gTitleMenuSelectionFade == 0xff)) {
        titleScreenFn_801368a4(1);
        gTitleMenuLoadDelay = 1;
        titleScreenFn_80130464(1);
        Sfx_PlayFromObject(0,0xff);
        if (gTitleMenuSelection == 2) {
          gTitleMenuNextDllId = 7;
          lbl_803DD6F8 = 1;
        } else if (gTitleMenuSelection < 2) {
          if (gTitleMenuSelection == 0) {
            gTitleMenuNextDllId = 5;
          } else {
            gTitleMenuNextDllId = 7;
            lbl_803DD6F8 = 0;
          }
        } else if (gTitleMenuSelection < 4) {
          gTitleMenuNextDllId = 7;
          lbl_803DD6F8 = 2;
        }
        return 0;
      }
      titleScreenFn_801368a4(0);
    }
    return 0;
  }

  if (((previousFadeTimer < 0xd) || (gTitleMenuLoadDelay > 0xc)) && (gTitleMenuLoadDelay < 1)) {
    TitleMenu_ClearPanel();
    titleScreenFn_8005cdd4(0);
    setLinkNotRotated();
    loadUiDll(gTitleMenuNextDllId);
  }
  return (uint)((uint)(int)gTitleMenuLoadDelay < 0xd) - ((int)gTitleMenuLoadDelay >> 0x1f);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void TitleMenu_release(void)
{
  setLinkNotRotated();
  titleScreenFn_80130464(1);
  saveFn_8007d960(1);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void TitleMenu_setSelection(int selection)
{
  u8 v = (u8)selection;
  gTitleMenuSelection = v;
  gTitleMenuPreviousSelection = 0xff;
  (*(*(void (**)(int))((int)gTitleMenuLinkInterface->vtable + 0x18)))(v);
}
#pragma peephole reset
#pragma scheduling reset
