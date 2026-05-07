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
extern undefined4 FUN_80118470();
extern undefined4 FUN_80118524();
extern bool FUN_80118574();
extern undefined8 FUN_80118d44();
extern undefined4 FUN_80118ed8();
extern undefined4 FUN_80118fc8();
extern int FUN_80119000();
extern undefined4 FUN_8011943c();
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
extern char s_starfox_thp_8031a32c[];
extern char s__________________malloc_for_movi_8031a338[];
extern char s__________________RESTRUCT_for_mo_8031a364[];
extern char s_n_attractmode_c_8031a38c[];
extern char s_Fail_to_prepare_8031a39c[];

extern void *mmAlloc(int size,int heap,int flags);
extern int mmSetFreeDelay(int delay);
extern void fn_80023800(void *ptr);
extern void fn_80022D58(int param_1);
extern void fn_80041E3C(int param_1);
extern void OSReport(const char *fmt,...);
extern void OSPanic(const char *file,int line,const char *msg,...);
extern void DCInvalidateRange(void *addr,uint nBytes);
extern void VIWaitForRetrace(void);

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
extern int lbl_803DD698;
extern u16 *lbl_803DCCF0;

struct NAttractModeMovieDims {
  int width;
  int height;
};

#define NATTRACTMODE_PREPARE_FAIL_LINE 0x2FB
#define NATTRACTMODE_MOVIE_HEAP 0x18
#define NATTRACTMODE_WORK_BUFFER_SIZE 0x4000
#define sNAttractModeSourceFile s_n_attractmode_c_8031a38c
#define sNAttractModeFailToPrepare s_Fail_to_prepare_8031a39c

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
void FUN_80115fbc(void)
{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  int *piVar6;
  int iVar7;
  uint *puVar8;
  double dVar9;
  
  FUN_80286838();
  iVar1 = FUN_80241de8();
  iVar1 = iVar1 + -0x40000;
  iVar5 = 0;
  piVar6 = &DAT_803a5098;
  do {
    *piVar6 = iVar1;
    iVar7 = *piVar6;
    *(undefined4 *)(iVar7 + 0x40) = 0;
    *(undefined *)(iVar7 + 0x48) = 0;
    puVar8 = (uint *)(iVar7 + 0x20);
    FUN_8025aa74(puVar8,iVar7 + 0x60,(uint)*(ushort *)(iVar7 + 10),(uint)*(ushort *)(iVar7 + 0xc),
                 (uint)*(byte *)(iVar7 + 0x16),(uint)*(byte *)(iVar7 + 0x17),
                 (uint)*(byte *)(iVar7 + 0x18),'\0');
    dVar9 = (double)FLOAT_803e2970;
    FUN_8025ace8(dVar9,dVar9,dVar9,puVar8,(uint)*(byte *)(iVar7 + 0x19),
                 (uint)*(byte *)(iVar7 + 0x1a),0,'\0',0);
    FUN_8025ae7c((int)puVar8,iVar7);
    iVar2 = FUN_8025aea4((int)puVar8);
    uVar3 = FUN_8025ae84((int)puVar8);
    uVar4 = FUN_8025ae94((int)puVar8);
    iVar2 = FUN_8025a850(uVar3,uVar4,iVar2,'\0',0);
    *(int *)(iVar7 + 0x44) = iVar2;
    iVar1 = iVar1 + *(int *)(*piVar6 + 0x44) + 0x60;
    piVar6 = piVar6 + 1;
    iVar5 = iVar5 + 1;
  } while (iVar5 < 3);
  DAT_803de264 = 0;
  DAT_803de260 = 0;
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801160e4
 * EN v1.0 Address: 0x801160E4
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x80116110
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801160e4(void)
{
  if (DAT_803de268 != '\0') {
    DAT_803de268 = '\0';
    FLOAT_803de26c = FLOAT_803e2980;
    FUN_80006b84(4);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80116128
 * EN v1.0 Address: 0x80116128
 * EN v1.0 Size: 500b
 * EN v1.1 Address: 0x8011615C
 * EN v1.1 Size: 252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80116128(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  undefined8 uVar1;
  
  DAT_803de268 = 1;
  FLOAT_803de26c = FLOAT_803e2980;
  FUN_80043030(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar1 = FUN_80040d94();
  FUN_80041ff8(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x3f);
  uVar1 = FUN_80040d88();
  uVar1 = FUN_80080f24(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar1 = FUN_8011d9b0(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar1 = FUN_801010b4(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  FUN_80053c98(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x12,'\0',param_11,
               param_12,param_13,param_14,param_15,param_16);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011631c
 * EN v1.0 Address: 0x8011631C
 * EN v1.0 Size: 264b
 * EN v1.1 Address: 0x80116258
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8011631c(void)
{
  byte bVar1;
  
  bVar1 = DAT_803dc070;
  FUN_800723a0();
  if (3 < bVar1) {
    bVar1 = 3;
  }
  if ('\0' < DAT_803de281) {
    DAT_803de281 = DAT_803de281 - bVar1;
  }
  if (DAT_803de280 != '\0') {
    FUN_80017698(0x44f,0);
    FUN_80006b84(4);
  }
  DAT_803de270 = DAT_803de270 + (uint)DAT_803dc070;
  if (0x26c < DAT_803de270) {
    DAT_803de282 = '\x01';
  }
  if (DAT_803de282 != '\0') {
    (**(code **)(*DAT_803dd6cc + 8))(0x1e,1);
    DAT_803de281 = '-';
    DAT_803de280 = '\x01';
  }
  if ('\0' < DAT_803de274) {
    FLOAT_803de27c = FLOAT_803de27c - FLOAT_803dc074;
  }
  if ('\x02' < DAT_803de274) {
    FLOAT_803de278 = FLOAT_803de278 - FLOAT_803dc074;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80116424
 * EN v1.0 Address: 0x80116424
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x8011637C
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80116424(void)
{
  FUN_80006b1c(0);
  DAT_803de270 = 0;
  DAT_803de274 = 0;
  DAT_803de282 = 0;
  DAT_803de281 = 0;
  DAT_803de280 = 0;
  return;
}

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
void n_attractmode_releaseMovieBuffers(void)
{
  int freeDelay;
  
  if (lbl_803DD610 == 2) {
    FUN_80118470();
    FUN_80118fc8();
    FUN_8011943c();
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
    lbl_803DD610 = 4;
    lbl_803DD619 = 1;
  }
  return;
}

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
  
  lbl_803DD619 = 1;
  iVar1 = FUN_80119478(2);
  if (iVar1 != 0) {
    iVar1 = FUN_80119000(s_starfox_thp_8031a32c,0);
    if (iVar1 == 0) {
      FUN_8011943c();
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
      if (local_24 == 0) {
        lbl_803DD624 = 0;
      }
      else {
        lbl_803DD624 = mmAlloc(local_24,NATTRACTMODE_MOVIE_HEAP,0);
      }
      lbl_803DD620 = mmAlloc(workBufferSize,NATTRACTMODE_MOVIE_HEAP,0);
      lbl_803DD61C = mmAlloc(NATTRACTMODE_WORK_BUFFER_SIZE,NATTRACTMODE_MOVIE_HEAP,0);
      if (((((lbl_803DD634 == 0) || (lbl_803DD630 == 0)) || (lbl_803DD62C == 0)) ||
          ((lbl_803DD628 == 0 || ((lbl_803DD624 == 0 && (local_24 != 0)))))) ||
         ((lbl_803DD620 == 0 || (lbl_803DD61C == 0)))) {
        FUN_8011943c();
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
        lbl_803DD619 = 0;
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
        lbl_803DD610 = 2;
        VIWaitForRetrace();
        lbl_803DD64D = 10;
        lbl_803DD698 = 0;
        if (lbl_803DD614 == 4) {
          FUN_80117c30(100,1);
        }
        else {
          FUN_80117c30(0,1);
        }
      }
    }
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void n_rareware_release(void) {}
void TitleMenu_frameEnd(void) {}
