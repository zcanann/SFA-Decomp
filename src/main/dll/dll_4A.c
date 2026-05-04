#include "ghidra_import.h"
#include "main/dll/dll_4A.h"

extern undefined8 FUN_80006824();
extern undefined4 FUN_80006b68();
extern undefined4 FUN_80006b84();
extern undefined8 FUN_80006ba8();
extern undefined4 FUN_80006bb0();
extern char FUN_80006bd0();
extern uint FUN_80006c00();
extern undefined4 FUN_80017468();
extern undefined4 FUN_800e8f58();

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
extern f32 lbl_803DE350;
extern f32 lbl_803DE354;
extern f32 lbl_803DE360;
extern f32 lbl_803E2A30;
extern f32 lbl_803E2A34;
extern f32 lbl_803E2A38;
extern f32 lbl_803E2A3C;
extern f32 lbl_803E2A40;
extern f32 lbl_803E2A44;
extern f32 lbl_803E2A48;
extern undefined uRam803de371;
extern undefined2 uRam803de372;
extern undefined uRam803de373;

/*
 * --INFO--
 *
 * Function: FUN_8011b868
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
FUN_8011b868(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,undefined4 param_5
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
  
  cVar5 = FUN_80006bd0(0);
  FUN_80006bb0(0);
  if ((int)cVar5 == 0) {
    if (DAT_803de35a == '\0') {
      lbl_803DE354 = lbl_803E2A34;
    }
    else if (DAT_803de364 < 0x14) {
      lbl_803DE354 = lbl_803E2A38;
    }
    else {
      lbl_803DE354 = lbl_803E2A3C;
    }
  }
  else {
    DAT_803de35a = '\0';
    lbl_803DE354 =
         lbl_803E2A30 *
         (float)((double)CONCAT44(0x43300000,(int)cVar5 ^ 0x80000000) - DOUBLE_803e2a28);
    if (lbl_803DE354 * lbl_803DE350 < lbl_803E2A34) {
      lbl_803DE354 = lbl_803E2A34;
    }
  }
  if (lbl_803E2A34 <= lbl_803DE350) {
    if (lbl_803E2A34 < lbl_803DE350) {
      lbl_803DE360 = lbl_803DE360 + lbl_803DE350;
      bVar1 = (float)((double)CONCAT44(0x43300000,DAT_803de368 + DAT_803a9390 / 2) - DOUBLE_803e2a20
                     ) <= lbl_803DE360;
      if (bVar1) {
        lbl_803DE360 =
             lbl_803DE360 - (float)((double)CONCAT44(0x43300000,DAT_803de368) - DOUBLE_803e2a20);
      }
      param_3 = DAT_803de368;
      if ((DAT_803de364 < 0x27) &&
         (param_3 = *(int *)(&DAT_803a92f4 + DAT_803de364 * 4),
         (float)((double)CONCAT44(0x43300000,
                                  param_3 + *(int *)(&DAT_803a9394 + DAT_803de364 * 4) / 2 ^
                                  0x80000000) - DOUBLE_803e2a28) <= lbl_803DE360)) {
        bVar1 = true;
      }
      if (bVar1) {
        if (lbl_803E2A34 == lbl_803DE354) {
          lbl_803DE350 = lbl_803E2A34;
        }
        iVar2 = DAT_803de364 + 1;
        if (0x27 < DAT_803de364 + 1) {
          iVar2 = DAT_803de364 + -0x27;
        }
        DAT_803de364 = iVar2;
        if ((DAT_803de364 == 0x27) && (DAT_803de35a != '\0')) {
          DAT_803de35a = '\0';
          lbl_803DE354 = lbl_803E2A34;
          lbl_803DE350 = lbl_803E2A34;
        }
      }
    }
  }
  else {
    lbl_803DE360 = lbl_803DE360 + lbl_803DE350;
    bVar1 = lbl_803DE360 <=
            (float)((double)CONCAT44(0x43300000,-DAT_803a942c / 2 ^ 0x80000000) - DOUBLE_803e2a28);
    if (bVar1) {
      lbl_803DE360 =
           lbl_803DE360 + (float)((double)CONCAT44(0x43300000,DAT_803de368) - DOUBLE_803e2a20);
    }
    if ((0 < DAT_803de364) &&
       (param_3 = DAT_803de364 * 4,
       lbl_803DE360 <=
       (float)((double)CONCAT44(0x43300000,
                                (&DAT_803a92f0)[DAT_803de364] -
                                *(int *)(&DAT_803a938c + param_3) / 2 ^ 0x80000000) -
              DOUBLE_803e2a28))) {
      bVar1 = true;
    }
    if (bVar1) {
      if (lbl_803E2A34 == lbl_803DE354) {
        lbl_803DE350 = lbl_803E2A34;
      }
      iVar2 = DAT_803de364 + -1;
      if (DAT_803de364 + -1 < 0) {
        iVar2 = DAT_803de364 + 0x27;
      }
      DAT_803de364 = iVar2;
      if ((DAT_803de364 == 0x27) && (DAT_803de35a != '\0')) {
        lbl_803DE354 = lbl_803E2A34;
        lbl_803DE350 = lbl_803E2A34;
        DAT_803de35a = '\0';
      }
    }
  }
  dVar7 = (double)lbl_803DE360;
  DAT_803de35c = DAT_803de368;
  if ((double)(float)((double)CONCAT44(0x43300000,DAT_803de368 >> 2) - DOUBLE_803e2a20) <= dVar7) {
    DAT_803de35c = 0;
  }
  dVar8 = (double)lbl_803DE350;
  if (((double)lbl_803E2A34 != dVar8) || ((double)lbl_803E2A34 != (double)lbl_803DE354)) {
    if ((dVar8 < (double)lbl_803E2A34) || ((double)lbl_803DE354 < (double)lbl_803E2A34)) {
      if (dVar8 <= (double)lbl_803E2A40) {
        dVar7 = (double)lbl_803E2A44;
        lbl_803DE350 =
             (float)(dVar7 * (double)(float)((double)lbl_803DE354 - dVar8) +
                    (double)lbl_803DE350);
      }
      else {
        lbl_803DE350 = lbl_803E2A40;
      }
    }
    else if ((double)lbl_803E2A48 <= dVar8) {
      dVar7 = (double)lbl_803E2A44;
      lbl_803DE350 =
           (float)(dVar7 * (double)(float)((double)lbl_803DE354 - dVar8) + (double)lbl_803DE350)
      ;
    }
    else {
      lbl_803DE350 = lbl_803E2A48;
    }
  }
  if ((cVar5 == '\0') && (lbl_803E2A34 == lbl_803DE350)) {
    uVar3 = FUN_80006c00(0);
    uVar6 = FUN_80006ba8(0,uVar3);
    if ((uVar3 & 0x100) == 0) {
      if ((uVar3 & 0x200) != 0) {
        DAT_803de35a = '\0';
        FUN_80006824(0,0x419);
        if (DAT_803de374 == 0) {
          FUN_80006b84(5);
          FUN_80006b68(5);
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
               FUN_80017468(uVar6,dVar7,dVar8,in_f4,in_f5,in_f6,in_f7,in_f8,
                            (uint)(ushort)(&DAT_8031b4d0)[DAT_803de364],extraout_r4,param_3,param_4,
                            param_5,param_6,param_7,param_8);
      uVar3 = (uint)DAT_803de374;
      DAT_803de374 = DAT_803de374 + 1;
      (&DAT_803de370)[uVar3] = *puVar4;
      (&DAT_803de370)[DAT_803de374] = 0;
      DAT_803de36c = 2;
      FUN_80006824(0,0x41a);
      if (DAT_803de374 == 3) {
        DAT_803de35a = '\x01';
      }
    }
    else if ((DAT_803de364 == 0x26) && (DAT_803de374 != 0)) {
      FUN_80006824(0,0x419);
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
      uVar6 = FUN_80006824(0,0x418);
      FUN_800e8f58(uVar6,dVar7,dVar8,in_f4,in_f5,in_f6,in_f7,in_f8);
      FUN_80006b84(5);
      DAT_803de36c = 2;
    }
  }
  return 0;
}
