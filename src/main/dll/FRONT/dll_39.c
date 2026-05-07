#include "ghidra_import.h"
#include "main/dll/FRONT/dll_39.h"

extern undefined4 FUN_80006b1c();
extern undefined4 FUN_80006b84();
extern undefined4 FUN_80017698();
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
extern undefined4 FUN_80117c30();
extern undefined4 FUN_80118164();
extern undefined4 fn_8011881C();
extern undefined4 FUN_80118524();
extern bool FUN_80118574();
extern undefined8 FUN_80118d44();
extern undefined4 FUN_80118ed8();
extern undefined4 fn_80118FAC();
extern int FUN_80119000();
extern undefined4 fn_801192EC();
extern int FUN_80119478();
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
extern void fn_8001B444(void *callback);
extern void GameBit_Set(int eventId,int value);
extern u8 fn_80134BBC(u8 *obj);
extern void fn_801349C8(void);
extern void fn_80134C28(u8 param_1);
extern void fn_80134D40(int param_1,int param_2,int param_3);
extern void fn_80135820(f32 param_1,f32 param_2);
extern void fn_80135A90(void);

extern int DAT_803a5098;
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
static char s_starfox_thp_8031a32c[] = "starfox.thp";
static char s__________________malloc_for_movi_8031a338[] =
    "^^^^^^^^^^^^^^^^  malloc for movie failed\n";
static char s__________________RESTRUCT_for_mo_8031a364[] =
    "^^^^^^^^^^^^^^^^  RESTRUCT for movie\n";
static char s_n_attractmode_c_8031a38c[] = "n_attractmode.c";
static char s_Fail_to_prepare_8031a39c[] = "Fail to prepare\n";

extern void *mmAlloc(int size,int heap,int flags);
extern int mmSetFreeDelay(int delay);
extern void fn_80023800(void *ptr);
extern void fn_80022D58(int param_1);
extern void fn_80041E3C(int param_1);
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
extern struct NAttractModeMovieDims lbl_803DD638;
extern int lbl_803DD640;
extern int lbl_803DD644;
extern u8 lbl_803DD64D;
extern u8 lbl_803DD64F;
extern int lbl_803DD698;
extern u16 *lbl_803DCCF0;
extern f32 lbl_803E1D10;
extern f32 lbl_803E1D14;
extern f32 lbl_803E1D18;

struct NAttractModeMovieDims {
  int width;
  int height;
};

#define NATTRACTMODE_PREPARE_FAIL_LINE 0x2FB
#define NATTRACTMODE_MOVIE_HEAP 0x18
#define NATTRACTMODE_WORK_BUFFER_SIZE 0x4000
#define NATTRACTMODE_MOVIE_STATE_PREPARED 2
#define NATTRACTMODE_MOVIE_STATE_RELEASED 4
#define NATTRACTMODE_MOVIE_BUSY 1
#define NATTRACTMODE_MOVIE_READY 0
#define NATTRACTMODE_OPTIONAL_BUFFER_SIZE_NONE 0
#define NATTRACTMODE_MOVIE_SETUP_ID 2
#define NATTRACTMODE_MOVIE_START_FRAME_DEFAULT 0
#define NATTRACTMODE_MOVIE_START_FRAME_ALTERNATE 100
#define NATTRACTMODE_MOVIE_RETRACE_COUNTDOWN 10
#define sNAttractModeSourceFile s_n_attractmode_c_8031a38c
#define sNAttractModeFailToPrepare s_Fail_to_prepare_8031a39c
#define sNAttractModeMoviePath s_starfox_thp_8031a32c

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
int fn_80115FBC(void)
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
 * Function: fn_801160E0
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
void fn_801160E0(void)
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
  
  if (lbl_803DD610 == NATTRACTMODE_MOVIE_STATE_PREPARED) {
    fn_8011881C();
    fn_80118FAC();
    fn_801192EC();
    freeDelay = mmSetFreeDelay(0);
    if (lbl_803DD634 != 0) {
      fn_80023800(lbl_803DD634);
      lbl_803DD634 = 0;
    }
    if (lbl_803DD630 != 0) {
      fn_80023800(lbl_803DD630);
      lbl_803DD630 = 0;
    }
    if (lbl_803DD62C != 0) {
      fn_80023800(lbl_803DD62C);
      lbl_803DD62C = 0;
    }
    if (lbl_803DD628 != 0) {
      fn_80023800(lbl_803DD628);
      lbl_803DD628 = 0;
    }
    if (lbl_803DD624 != 0) {
      fn_80023800(lbl_803DD624);
      lbl_803DD624 = 0;
    }
    if (lbl_803DD620 != 0) {
      fn_80023800(lbl_803DD620);
      lbl_803DD620 = 0;
    }
    if (lbl_803DD61C != 0) {
      fn_80023800(lbl_803DD61C);
      lbl_803DD61C = 0;
    }
    mmSetFreeDelay(freeDelay);
    lbl_803DD610 = NATTRACTMODE_MOVIE_STATE_RELEASED;
    lbl_803DD619 = NATTRACTMODE_MOVIE_BUSY;
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
  int iVar1;
  int freeDelay;
  int local_18;
  int local_1c;
  int local_20;
  int local_24;
  int workBufferSize;
  uint local_14 [3];
  
  lbl_803DD619 = NATTRACTMODE_MOVIE_BUSY;
  iVar1 = FUN_80119478(NATTRACTMODE_MOVIE_SETUP_ID);
  if (iVar1 != 0) {
    iVar1 = FUN_80119000(sNAttractModeMoviePath,NATTRACTMODE_MOVIE_START_FRAME_DEFAULT);
    if (iVar1 == 0) {
      fn_801192EC();
    }
    else {
      FUN_80118164((uint)&lbl_803DD638);
      lbl_803DD644 = ((uint)lbl_803DCCF0[2] - lbl_803DD638.width) >> 1;
      lbl_803DD640 = ((uint)lbl_803DCCF0[3] - lbl_803DD638.height) >> 1;
      FUN_80118ed8(local_14,&local_18,&local_1c,&local_20,&local_24,&workBufferSize);
      lbl_803DD634 = mmAlloc(local_14[0],NATTRACTMODE_MOVIE_HEAP,0);
      lbl_803DD630 = mmAlloc(local_18,NATTRACTMODE_MOVIE_HEAP,0);
      lbl_803DD62C = mmAlloc(local_1c,NATTRACTMODE_MOVIE_HEAP,0);
      lbl_803DD628 = mmAlloc(local_20,NATTRACTMODE_MOVIE_HEAP,0);
      if (local_24 == NATTRACTMODE_OPTIONAL_BUFFER_SIZE_NONE) {
        lbl_803DD624 = 0;
      }
      else {
        lbl_803DD624 = mmAlloc(local_24,NATTRACTMODE_MOVIE_HEAP,0);
      }
      lbl_803DD620 = mmAlloc(workBufferSize,NATTRACTMODE_MOVIE_HEAP,0);
      lbl_803DD61C = mmAlloc(NATTRACTMODE_WORK_BUFFER_SIZE,NATTRACTMODE_MOVIE_HEAP,0);
      if (((((lbl_803DD634 == 0) || (lbl_803DD630 == 0)) || (lbl_803DD62C == 0)) ||
          ((lbl_803DD628 == 0 ||
           ((lbl_803DD624 == 0 && (local_24 != NATTRACTMODE_OPTIONAL_BUFFER_SIZE_NONE)))))) ||
         ((lbl_803DD620 == 0 || (lbl_803DD61C == 0)))) {
        fn_801192EC();
        freeDelay = mmSetFreeDelay(0);
        if (lbl_803DD634 != 0) {
          fn_80023800(lbl_803DD634);
          lbl_803DD634 = 0;
        }
        if (lbl_803DD630 != 0) {
          fn_80023800(lbl_803DD630);
          lbl_803DD630 = 0;
        }
        if (lbl_803DD62C != 0) {
          fn_80023800(lbl_803DD62C);
          lbl_803DD62C = 0;
        }
        if (lbl_803DD628 != 0) {
          fn_80023800(lbl_803DD628);
          lbl_803DD628 = 0;
        }
        if (lbl_803DD624 != 0) {
          fn_80023800(lbl_803DD624);
          lbl_803DD624 = 0;
        }
        if (lbl_803DD620 != 0) {
          fn_80023800(lbl_803DD620);
          lbl_803DD620 = 0;
        }
        if (lbl_803DD61C != 0) {
          fn_80023800(lbl_803DD61C);
          lbl_803DD61C = 0;
        }
        mmSetFreeDelay(freeDelay);
        OSReport(s__________________malloc_for_movi_8031a338);
        fn_80022D58(1);
        fn_80041E3C(0);
        OSReport(s__________________RESTRUCT_for_mo_8031a364);
        fn_80022D58(1);
      }
      else {
        lbl_803DD619 = NATTRACTMODE_MOVIE_READY;
        DCInvalidateRange(lbl_803DD634,local_14[0]);
        DCInvalidateRange(lbl_803DD630,local_18);
        DCInvalidateRange(lbl_803DD62C,local_1c);
        DCInvalidateRange(lbl_803DD628,local_20);
        if (lbl_803DD624 != 0) {
          DCInvalidateRange(lbl_803DD624,local_24);
        }
        DCInvalidateRange(lbl_803DD620,workBufferSize);
        DCInvalidateRange(lbl_803DD61C,NATTRACTMODE_WORK_BUFFER_SIZE);
        FUN_80118d44(lbl_803DD634,lbl_803DD630,lbl_803DD62C,lbl_803DD628,lbl_803DD624,
                     lbl_803DD620);
        iVar1 = FUN_80118574(0,1);
        if (iVar1 == 0) {
          OSPanic(sNAttractModeSourceFile,NATTRACTMODE_PREPARE_FAIL_LINE,
                  sNAttractModeFailToPrepare);
        }
        FUN_80118524();
        lbl_803DD610 = NATTRACTMODE_MOVIE_STATE_PREPARED;
        VIWaitForRetrace();
        lbl_803DD64D = NATTRACTMODE_MOVIE_RETRACE_COUNTDOWN;
        lbl_803DD698 = 0;
        if (lbl_803DD614 == NATTRACTMODE_MOVIE_STATE_RELEASED) {
          FUN_80117c30(NATTRACTMODE_MOVIE_START_FRAME_ALTERNATE,1);
        }
        else {
          FUN_80117c30(NATTRACTMODE_MOVIE_START_FRAME_DEFAULT,1);
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
 * Function: fn_801165BC
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
void fn_801165BC(u8 *param_1)
{
  int menuAction;

  if (fn_80134BBC(param_1) != 0) {
    fn_801349C8();
    return;
  }

  menuAction = (*(code *)(*lbl_803DCA50 + 0x10))();
  if (menuAction == 0x57) {
    fn_8001B444(fn_80135A90);
    fn_80135820(lbl_803E1D10 + (f32)(lbl_803DD616 * 0x1a4) / lbl_803E1D14,
                lbl_803E1D18);
    fn_80134D40(0,0,0);
    (*(code *)(*lbl_803DCA4C + 0x18))();
    (*(code *)(*lbl_803DCAA0 + 0x30))(0xff);
    (*(code *)(*lbl_803DCAA0 + 0x10))(param_1);
    fn_8001B444(0);
    fn_80134C28(lbl_803DD64F);
  }
}
#pragma peephole reset
#pragma scheduling reset

/* Trivial 4b 0-arg blr leaves. */
void TitleMenu_frameEnd(void) {}
