#include "ghidra_import.h"
#include "main/dll/FRONT/dll_39.h"

extern undefined4 FUN_80006b1c();
extern undefined4 FUN_80006b84();
extern undefined4 FUN_800177c4();
extern undefined8 FUN_80040d88();
extern undefined8 FUN_80040d94();
extern undefined4 FUN_80040da0();
extern undefined4 FUN_80041ff8();
extern undefined4 FUN_80043030();
extern undefined4 FUN_80053c98();
extern undefined4 FUN_800723a0();
extern undefined8 FUN_80080f24();
extern undefined8 FUN_801010b4();
extern undefined4 movieFn_80117b68();
extern undefined4 fn_801181F8();
extern undefined4 fn_8011881C();
extern undefined4 fn_80118900();
extern bool prepareAttractMode();
extern undefined8 fn_80118C88();
extern undefined4 fn_80118EAC();
extern undefined4 fn_80118FAC();
extern int movieLoad();
extern undefined4 audioFn_801192ec();
extern int attractModeAudioFn_80119338();
extern undefined8 FUN_8011d9b0();
extern int FUN_80241de8();
extern undefined4 FUN_802420b0();
extern undefined4 FUN_8024d054();
extern int FUN_8025a850();
extern undefined4 FUN_8025aa74();
extern undefined4 FUN_8025ace8();
extern undefined4 FUN_8025ae7c();
extern uint FUN_8025ae84();
extern uint FUN_8025ae94();
extern int FUN_8025aea4();
extern undefined4 FUN_80286838();
extern undefined4 FUN_80286884();
extern void fn_8001404C(int param_1);
extern void loadUiDll(int dllNo);
extern void gameTextSetDrawFunc(void *callback);
extern void GameBit_Set(int eventId,int value);
extern u8 shouldShowCredits(u8 *obj);
extern void creditsStart_(void);
extern void titleScreenShowCopyright(u8 param_1);
extern void gameTextBoxFn_80134d40(int param_1,int param_2,int param_3);
extern void titleScreenPositionElements(f32 param_1,f32 param_2);
extern void titleScreenTextDrawFunc(void);

extern int DAT_803a5098;
extern char lbl_8031A1D8[];
extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6cc;
extern undefined4 DAT_803dd970;
extern undefined4 DAT_803de260;
extern undefined4 DAT_803de264;
extern undefined4 DAT_803de268;
extern undefined4 DAT_803de270;
extern undefined4 DAT_803de274;
extern undefined4 DAT_803de280;
extern undefined4 DAT_803de281;
extern undefined4 DAT_803de282;
extern undefined4 DAT_803de288;
extern undefined4 DAT_803de28c;
extern undefined4 DAT_803de291;
extern undefined4 DAT_803de29c;
extern undefined4 DAT_803de2a0;
extern undefined4 DAT_803de2a4;
extern undefined4 DAT_803de2a8;
extern undefined4 DAT_803de2ac;
extern undefined4 DAT_803de2b0;
extern undefined4 DAT_803de2b4;
extern undefined4 DAT_803de2b8;
extern undefined4 DAT_803de2c0;
extern undefined4 DAT_803de2c4;
extern undefined4 DAT_803de2cd;
extern undefined4 DAT_803de318;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803de26c;
extern f32 FLOAT_803de278;
extern f32 FLOAT_803de27c;
extern f32 FLOAT_803e2970;
extern f32 FLOAT_803e2980;
extern int iRam803de2bc;
static char sNRarewareReportTag[] = "n_rareware\n";

extern void *mmAlloc(int size,int heap,int flags);
extern int mmSetFreeDelay(int delay);
extern void mm_free(void *ptr);
extern void printHeapStats(int param_1);
extern void defragMemory(int param_1);
extern void OSReport(const char *fmt,...);
extern void OSPanic(const char *file,int line,const char *msg,...);
extern void DCInvalidateRange(void *addr,uint nBytes);
extern void VIWaitForRetrace(void);

extern u8 framesThisStep;
extern f32 timeDelta;
extern undefined4 *lbl_803DCA4C;
extern undefined4 *lbl_803DCA50;
extern undefined4 *lbl_803DCAA0;
extern int lbl_803DD5F8;
extern s8 lbl_803DD5FC;
extern f32 lbl_803DD600;
extern f32 lbl_803DD604;
extern u8 lbl_803DD608;
extern s8 lbl_803DD609;
extern u8 lbl_803DD60A;
extern u8 lbl_803DD616;
extern int lbl_803DD610;
extern u8 lbl_803DD614;
extern u8 lbl_803DD619;
extern void *lbl_803DD61C;
extern void *lbl_803DD620;
extern void *lbl_803DD624;
extern void *lbl_803DD628;
extern void *lbl_803DD62C;
extern void *lbl_803DD630;
extern void *lbl_803DD634;
extern NAttractModeMovieDims lbl_803DD638;
extern int lbl_803DD640;
extern int lbl_803DD644;
extern u8 lbl_803DD64D;
extern u8 lbl_803DD64F;
extern int lbl_803DD698;
extern u16 *lbl_803DCCF0;
extern f32 lbl_803E1D10;
extern f32 lbl_803E1D14;
extern f32 lbl_803E1D18;

#define NATTRACTMODE_MOVIE_PATH_OFFSET 0x154
#define NATTRACTMODE_MALLOC_FAILED_OFFSET 0x160
#define NATTRACTMODE_RESTRUCT_MOVIE_OFFSET 0x18C
#define NATTRACTMODE_SOURCE_FILE_OFFSET 0x1B4
#define NATTRACTMODE_FAIL_TO_PREPARE_OFFSET 0x1C4

/*
 * --INFO--
 *
 * Function: FUN_80115fbc
 * EN v1.0 Address: 0x80115FBC
 * EN v1.0 Size: 296b
 * EN v1.1 Address: 0x80115FF0
 * EN v1.1 Size: 288b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int n_rareware_frameStart(void)
{
  int frameStep;

  frameStep = framesThisStep;
  OSReport(sNRarewareReportTag);
  if (frameStep > 3) {
    frameStep = 3;
  }
  if ((s8)lbl_803DD609 > 0) {
    lbl_803DD609 = (s8)(lbl_803DD609 - frameStep);
  }
  if ((s8)lbl_803DD608 != 0) {
    GameBit_Set(0x44f,0);
    loadUiDll(4);
  }
  lbl_803DD5F8 += framesThisStep;
  if (lbl_803DD5F8 > 0x26c) {
    lbl_803DD60A = 1;
  }
  if ((s8)lbl_803DD60A != 0) {
    (*(code *)(*lbl_803DCA4C + 8))(0x1e,1);
    lbl_803DD609 = 0x2d;
    lbl_803DD608 = 1;
  }
  if (lbl_803DD5FC > 0) {
    lbl_803DD604 -= timeDelta;
  }
  if (lbl_803DD5FC > 2) {
    lbl_803DD600 -= timeDelta;
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

void n_rareware_release(void) {}

/*
 * --INFO--
 *
 * Function: n_rareware_initialise
 * EN v1.0 Address: 0x801160E0
 * EN v1.0 Size: 60b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void n_rareware_initialise(void)
{
  fn_8001404C(0);
  lbl_803DD5F8 = 0;
  lbl_803DD5FC = 0;
  lbl_803DD60A = 0;
  lbl_803DD609 = 0;
  lbl_803DD608 = 0;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: n_attractmode_releaseMovieBuffers
 * EN v1.0 Address: 0x8011611C
 * EN v1.0 Size: 264b
 * EN v1.1 Address: 0x801163B8
 * EN v1.1 Size: 264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void n_attractmode_releaseMovieBuffers(void)
{
  int freeDelay;
  
  if (gAttractMovieState == NATTRACTMODE_MOVIE_STATE_PREPARED) {
    fn_8011881C();
    fn_80118FAC();
    audioFn_801192ec();
    freeDelay = mmSetFreeDelay(0);
    if (gAttractMovieBuffer0 != 0) {
      mm_free(gAttractMovieBuffer0);
      gAttractMovieBuffer0 = 0;
    }
    if (gAttractMovieBuffer1 != 0) {
      mm_free(gAttractMovieBuffer1);
      gAttractMovieBuffer1 = 0;
    }
    if (gAttractMovieBuffer2 != 0) {
      mm_free(gAttractMovieBuffer2);
      gAttractMovieBuffer2 = 0;
    }
    if (gAttractMovieBuffer3 != 0) {
      mm_free(gAttractMovieBuffer3);
      gAttractMovieBuffer3 = 0;
    }
    if (gAttractMovieOptionalBuffer != 0) {
      mm_free(gAttractMovieOptionalBuffer);
      gAttractMovieOptionalBuffer = 0;
    }
    if (gAttractMovieWorkBuffer != 0) {
      mm_free(gAttractMovieWorkBuffer);
      gAttractMovieWorkBuffer = 0;
    }
    if (gAttractMovieScratchBuffer != 0) {
      mm_free(gAttractMovieScratchBuffer);
      gAttractMovieScratchBuffer = 0;
    }
    mmSetFreeDelay(freeDelay);
    gAttractMovieState = NATTRACTMODE_MOVIE_STATE_RELEASED;
    gAttractMoviePreparePending = NATTRACTMODE_MOVIE_BUSY;
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: n_attractmode_prepareMovie
 * EN v1.0 Address: 0x80116224
 * EN v1.0 Size: 920b
 * EN v1.1 Address: 0x801164C0
 * EN v1.1 Size: 920b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void n_attractmode_prepareMovie(void)
{
  char *attractModeData;
  int ok;
  int freeDelay;
  int movieBuffer1Size;
  int movieBuffer2Size;
  int movieBuffer3Size;
  uint optionalBufferSize;
  int workBufferSize;
  uint movieBuffer0Size[3];
  
  attractModeData = lbl_8031A1D8;
  gAttractMoviePreparePending = NATTRACTMODE_MOVIE_BUSY;
  ok = attractModeAudioFn_80119338(NATTRACTMODE_MOVIE_SETUP_ID);
  if (ok != 0) {
    ok = movieLoad(attractModeData + NATTRACTMODE_MOVIE_PATH_OFFSET,
                   NATTRACTMODE_MOVIE_START_FRAME_DEFAULT);
    if (ok == 0) {
      audioFn_801192ec();
    }
    else {
      fn_801181F8((uint)&gAttractMovieDims);
      gAttractMovieOffsetX = ((uint)lbl_803DCCF0[2] - gAttractMovieDims.width) >> 1;
      gAttractMovieOffsetY = ((uint)lbl_803DCCF0[3] - gAttractMovieDims.height) >> 1;
      fn_80118EAC(movieBuffer0Size,&movieBuffer1Size,&movieBuffer2Size,&movieBuffer3Size,
                  &optionalBufferSize,&workBufferSize);
      gAttractMovieBuffer0 = mmAlloc(movieBuffer0Size[0],NATTRACTMODE_MOVIE_HEAP,0);
      gAttractMovieBuffer1 = mmAlloc(movieBuffer1Size,NATTRACTMODE_MOVIE_HEAP,0);
      gAttractMovieBuffer2 = mmAlloc(movieBuffer2Size,NATTRACTMODE_MOVIE_HEAP,0);
      gAttractMovieBuffer3 = mmAlloc(movieBuffer3Size,NATTRACTMODE_MOVIE_HEAP,0);
      if (optionalBufferSize != NATTRACTMODE_OPTIONAL_BUFFER_SIZE_NONE) {
        gAttractMovieOptionalBuffer = mmAlloc(optionalBufferSize,NATTRACTMODE_MOVIE_HEAP,0);
      }
      else {
        gAttractMovieOptionalBuffer = 0;
      }
      gAttractMovieWorkBuffer = mmAlloc(workBufferSize,NATTRACTMODE_MOVIE_HEAP,0);
      gAttractMovieScratchBuffer = mmAlloc(NATTRACTMODE_WORK_BUFFER_SIZE,NATTRACTMODE_MOVIE_HEAP,0);
      if (((((gAttractMovieBuffer0 == 0) || (gAttractMovieBuffer1 == 0)) ||
           (gAttractMovieBuffer2 == 0)) || ((gAttractMovieBuffer3 == 0 ||
           ((gAttractMovieOptionalBuffer == 0 &&
            (optionalBufferSize != NATTRACTMODE_OPTIONAL_BUFFER_SIZE_NONE)))))) ||
         ((gAttractMovieWorkBuffer == 0 || (gAttractMovieScratchBuffer == 0)))) {
        audioFn_801192ec();
        freeDelay = mmSetFreeDelay(0);
        if (gAttractMovieBuffer0 != 0) {
          mm_free(gAttractMovieBuffer0);
          gAttractMovieBuffer0 = 0;
        }
        if (gAttractMovieBuffer1 != 0) {
          mm_free(gAttractMovieBuffer1);
          gAttractMovieBuffer1 = 0;
        }
        if (gAttractMovieBuffer2 != 0) {
          mm_free(gAttractMovieBuffer2);
          gAttractMovieBuffer2 = 0;
        }
        if (gAttractMovieBuffer3 != 0) {
          mm_free(gAttractMovieBuffer3);
          gAttractMovieBuffer3 = 0;
        }
        if (gAttractMovieOptionalBuffer != 0) {
          mm_free(gAttractMovieOptionalBuffer);
          gAttractMovieOptionalBuffer = 0;
        }
        if (gAttractMovieWorkBuffer != 0) {
          mm_free(gAttractMovieWorkBuffer);
          gAttractMovieWorkBuffer = 0;
        }
        if (gAttractMovieScratchBuffer != 0) {
          mm_free(gAttractMovieScratchBuffer);
          gAttractMovieScratchBuffer = 0;
        }
        mmSetFreeDelay(freeDelay);
        OSReport(attractModeData + NATTRACTMODE_MALLOC_FAILED_OFFSET);
        printHeapStats(1);
        defragMemory(0);
        OSReport(attractModeData + NATTRACTMODE_RESTRUCT_MOVIE_OFFSET);
        printHeapStats(1);
      }
      else {
        gAttractMoviePreparePending = NATTRACTMODE_MOVIE_READY;
        DCInvalidateRange(gAttractMovieBuffer0,movieBuffer0Size[0]);
        DCInvalidateRange(gAttractMovieBuffer1,movieBuffer1Size);
        DCInvalidateRange(gAttractMovieBuffer2,movieBuffer2Size);
        DCInvalidateRange(gAttractMovieBuffer3,movieBuffer3Size);
        if (gAttractMovieOptionalBuffer != 0) {
          DCInvalidateRange(gAttractMovieOptionalBuffer,optionalBufferSize);
        }
        DCInvalidateRange(gAttractMovieWorkBuffer,workBufferSize);
        DCInvalidateRange(gAttractMovieScratchBuffer,NATTRACTMODE_WORK_BUFFER_SIZE);
        fn_80118C88(gAttractMovieBuffer0,gAttractMovieBuffer1,gAttractMovieBuffer2,
                     gAttractMovieBuffer3,gAttractMovieOptionalBuffer,gAttractMovieWorkBuffer);
        ok = prepareAttractMode(0,1);
        if (ok == 0) {
          OSPanic(attractModeData + NATTRACTMODE_SOURCE_FILE_OFFSET,
                  NATTRACTMODE_PREPARE_FAIL_LINE,
                  attractModeData + NATTRACTMODE_FAIL_TO_PREPARE_OFFSET);
        }
        fn_80118900();
        gAttractMovieState = NATTRACTMODE_MOVIE_STATE_PREPARED;
        VIWaitForRetrace();
        gAttractMovieRetraceCountdown = NATTRACTMODE_MOVIE_RETRACE_COUNTDOWN;
        gAttractMovieIdleFrameCount = 0;
        if ((int)gTitleMenuSelection == NATTRACTMODE_MOVIE_STATE_RELEASED) {
          movieFn_80117b68(NATTRACTMODE_MOVIE_START_FRAME_ALTERNATE,1);
        }
        else {
          movieFn_80117b68(NATTRACTMODE_MOVIE_START_FRAME_DEFAULT,1);
        }
      }
    }
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: TitleMenu_render
 * EN v1.0 Address: 0x801165BC
 * EN v1.0 Size: 264b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void TitleMenu_render(u8 *param_1)
{
  int menuAction;

  if (shouldShowCredits(param_1) != 0) {
    creditsStart_();
    return;
  }

  menuAction = (*(code *)(*lbl_803DCA50 + 0x10))();
  if (menuAction == 0x57) {
    gameTextSetDrawFunc(titleScreenTextDrawFunc);
    titleScreenPositionElements(lbl_803E1D10 + (f32)(lbl_803DD616 * 0x1a4) / lbl_803E1D14,
                lbl_803E1D18);
    gameTextBoxFn_80134d40(0,0,0);
    (*(code *)(*lbl_803DCA4C + 0x18))();
    (*(code *)(*lbl_803DCAA0 + 0x30))(0xff);
    (*(code *)(*lbl_803DCAA0 + 0x10))(param_1);
    gameTextSetDrawFunc(0);
    titleScreenShowCopyright(gAttractMoviePlaybackEnabled);
  }
}
#pragma peephole reset
#pragma scheduling reset

/* Trivial 4b 0-arg blr leaves. */
void TitleMenu_frameEnd(void) {}
