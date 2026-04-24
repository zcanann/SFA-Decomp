#include "ghidra_import.h"
#include "main/dll/dll_4A.h"

extern undefined8 FUN_8000bb38();
extern undefined4 FUN_80014954();
extern undefined4 FUN_80014974();
extern undefined8 FUN_80014b68();
extern undefined4 FUN_80014b94();
extern char FUN_80014cec();
extern uint FUN_80014e9c();
extern undefined4 FUN_8001947c();
extern undefined4 FUN_800e8d40();

extern undefined4 DAT_8031b4d0;
extern undefined4 DAT_803a92f0;
extern undefined4 DAT_803a92f4;
extern undefined4 DAT_803a938c;
extern undefined4 DAT_803a9390;
extern undefined4 DAT_803a9394;
extern undefined4 DAT_803a942c;
extern undefined4 DAT_803de35a;
extern undefined4 DAT_803de35c;
extern undefined4 DAT_803de364;
extern undefined4 DAT_803de368;
extern undefined4 DAT_803de36c;
extern undefined4 DAT_803de370;
extern undefined4 DAT_803de374;
extern f64 DOUBLE_803e2a20;
extern f64 DOUBLE_803e2a28;
extern f32 FLOAT_803de350;
extern f32 FLOAT_803de354;
extern f32 FLOAT_803de360;
extern f32 FLOAT_803e2a30;
extern f32 FLOAT_803e2a34;
extern f32 FLOAT_803e2a38;
extern f32 FLOAT_803e2a3c;
extern f32 FLOAT_803e2a40;
extern f32 FLOAT_803e2a44;
extern f32 FLOAT_803e2a48;
extern undefined uRam803de371;
extern undefined2 uRam803de372;
extern undefined uRam803de373;

/*
 * --INFO--
 *
 * Function: FUN_8011bb4c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x8011BB4C
 * EN v1.1 Size: 1540b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8011bb4c(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,undefined4 param_5
            ,undefined4 param_6,undefined4 param_7,undefined4 param_8)
{
  bool bVar1;
  int iVar2;
  char cVar5;
  uint uVar3;
  undefined *puVar4;
  undefined4 extraout_r4;
  undefined8 uVar6;
  double dVar7;
  double dVar8;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  
  cVar5 = FUN_80014cec(0);
  FUN_80014b94(0);
  if ((int)cVar5 == 0) {
    if (DAT_803de35a == '\0') {
      FLOAT_803de354 = FLOAT_803e2a34;
    }
    else if (DAT_803de364 < 0x14) {
      FLOAT_803de354 = FLOAT_803e2a38;
    }
    else {
      FLOAT_803de354 = FLOAT_803e2a3c;
    }
  }
  else {
    DAT_803de35a = '\0';
    FLOAT_803de354 =
         FLOAT_803e2a30 *
         (float)((double)CONCAT44(0x43300000,(int)cVar5 ^ 0x80000000) - DOUBLE_803e2a28);
    if (FLOAT_803de354 * FLOAT_803de350 < FLOAT_803e2a34) {
      FLOAT_803de354 = FLOAT_803e2a34;
    }
  }
  if (FLOAT_803e2a34 <= FLOAT_803de350) {
    if (FLOAT_803e2a34 < FLOAT_803de350) {
      FLOAT_803de360 = FLOAT_803de360 + FLOAT_803de350;
      bVar1 = (float)((double)CONCAT44(0x43300000,DAT_803de368 + DAT_803a9390 / 2) - DOUBLE_803e2a20
                     ) <= FLOAT_803de360;
      if (bVar1) {
        FLOAT_803de360 =
             FLOAT_803de360 - (float)((double)CONCAT44(0x43300000,DAT_803de368) - DOUBLE_803e2a20);
      }
      param_3 = DAT_803de368;
      if ((DAT_803de364 < 0x27) &&
         (param_3 = *(int *)(&DAT_803a92f4 + DAT_803de364 * 4),
         (float)((double)CONCAT44(0x43300000,
                                  param_3 + *(int *)(&DAT_803a9394 + DAT_803de364 * 4) / 2 ^
                                  0x80000000) - DOUBLE_803e2a28) <= FLOAT_803de360)) {
        bVar1 = true;
      }
      if (bVar1) {
        if (FLOAT_803e2a34 == FLOAT_803de354) {
          FLOAT_803de350 = FLOAT_803e2a34;
        }
        iVar2 = DAT_803de364 + 1;
        if (0x27 < DAT_803de364 + 1) {
          iVar2 = DAT_803de364 + -0x27;
        }
        DAT_803de364 = iVar2;
        if ((DAT_803de364 == 0x27) && (DAT_803de35a != '\0')) {
          DAT_803de35a = '\0';
          FLOAT_803de354 = FLOAT_803e2a34;
          FLOAT_803de350 = FLOAT_803e2a34;
        }
      }
    }
  }
  else {
    FLOAT_803de360 = FLOAT_803de360 + FLOAT_803de350;
    bVar1 = FLOAT_803de360 <=
            (float)((double)CONCAT44(0x43300000,-DAT_803a942c / 2 ^ 0x80000000) - DOUBLE_803e2a28);
    if (bVar1) {
      FLOAT_803de360 =
           FLOAT_803de360 + (float)((double)CONCAT44(0x43300000,DAT_803de368) - DOUBLE_803e2a20);
    }
    if ((0 < DAT_803de364) &&
       (param_3 = DAT_803de364 * 4,
       FLOAT_803de360 <=
       (float)((double)CONCAT44(0x43300000,
                                (&DAT_803a92f0)[DAT_803de364] -
                                *(int *)(&DAT_803a938c + param_3) / 2 ^ 0x80000000) -
              DOUBLE_803e2a28))) {
      bVar1 = true;
    }
    if (bVar1) {
      if (FLOAT_803e2a34 == FLOAT_803de354) {
        FLOAT_803de350 = FLOAT_803e2a34;
      }
      iVar2 = DAT_803de364 + -1;
      if (DAT_803de364 + -1 < 0) {
        iVar2 = DAT_803de364 + 0x27;
      }
      DAT_803de364 = iVar2;
      if ((DAT_803de364 == 0x27) && (DAT_803de35a != '\0')) {
        FLOAT_803de354 = FLOAT_803e2a34;
        FLOAT_803de350 = FLOAT_803e2a34;
        DAT_803de35a = '\0';
      }
    }
  }
  dVar7 = (double)FLOAT_803de360;
  DAT_803de35c = DAT_803de368;
  if ((double)(float)((double)CONCAT44(0x43300000,DAT_803de368 >> 2) - DOUBLE_803e2a20) <= dVar7) {
    DAT_803de35c = 0;
  }
  dVar8 = (double)FLOAT_803de350;
  if (((double)FLOAT_803e2a34 != dVar8) || ((double)FLOAT_803e2a34 != (double)FLOAT_803de354)) {
    if ((dVar8 < (double)FLOAT_803e2a34) || ((double)FLOAT_803de354 < (double)FLOAT_803e2a34)) {
      if (dVar8 <= (double)FLOAT_803e2a40) {
        dVar7 = (double)FLOAT_803e2a44;
        FLOAT_803de350 =
             (float)(dVar7 * (double)(float)((double)FLOAT_803de354 - dVar8) +
                    (double)FLOAT_803de350);
      }
      else {
        FLOAT_803de350 = FLOAT_803e2a40;
      }
    }
    else if ((double)FLOAT_803e2a48 <= dVar8) {
      dVar7 = (double)FLOAT_803e2a44;
      FLOAT_803de350 =
           (float)(dVar7 * (double)(float)((double)FLOAT_803de354 - dVar8) + (double)FLOAT_803de350)
      ;
    }
    else {
      FLOAT_803de350 = FLOAT_803e2a48;
    }
  }
  if ((cVar5 == '\0') && (FLOAT_803e2a34 == FLOAT_803de350)) {
    uVar3 = FUN_80014e9c(0);
    uVar6 = FUN_80014b68(0,uVar3);
    if ((uVar3 & 0x100) == 0) {
      if ((uVar3 & 0x200) != 0) {
        DAT_803de35a = '\0';
        FUN_8000bb38(0,0x419);
        if (DAT_803de374 == 0) {
          FUN_80014974(5);
          FUN_80014954(5);
        }
        else {
          DAT_803de374 = DAT_803de374 - 1;
          (&DAT_803de370)[DAT_803de374] = 0;
          DAT_803de36c = 2;
        }
      }
    }
    else if ((DAT_803de364 < 0x26) && (DAT_803de374 < 3)) {
      puVar4 = (undefined *)
               FUN_8001947c(uVar6,dVar7,dVar8,in_f4,in_f5,in_f6,in_f7,in_f8,
                            (uint)(ushort)(&DAT_8031b4d0)[DAT_803de364],extraout_r4,param_3,param_4,
                            param_5,param_6,param_7,param_8);
      uVar3 = (uint)DAT_803de374;
      DAT_803de374 = DAT_803de374 + 1;
      (&DAT_803de370)[uVar3] = *puVar4;
      (&DAT_803de370)[DAT_803de374] = 0;
      DAT_803de36c = 2;
      FUN_8000bb38(0,0x41a);
      if (DAT_803de374 == 3) {
        DAT_803de35a = '\x01';
      }
    }
    else if ((DAT_803de364 == 0x26) && (DAT_803de374 != 0)) {
      FUN_8000bb38(0,0x419);
      DAT_803de374 = DAT_803de374 - 1;
      (&DAT_803de370)[DAT_803de374] = 0;
      DAT_803de36c = 2;
      DAT_803de35a = '\0';
    }
    else if (DAT_803de364 == 0x27) {
      if (DAT_803de374 == 0) {
        DAT_803de370 = 0x46;
        uRam803de371 = 0x4f;
        uRam803de372 = 0x58;
        uRam803de373 = 0;
      }
      uVar6 = FUN_8000bb38(0,0x418);
      FUN_800e8d40(uVar6,dVar7,dVar8,in_f4,in_f5,in_f6,in_f7,in_f8);
      FUN_80014974(5);
      DAT_803de36c = 2;
    }
  }
  return 0;
}
