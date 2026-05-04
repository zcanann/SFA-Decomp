#include "ghidra_import.h"
#include "main/dll/dll_47.h"

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
extern void gameplay_applyPreviewSettingsForSlot();
extern undefined4 FUN_800e8ba4();
extern undefined4 FUN_800e8f58();
extern undefined4 FUN_800e9298();
extern undefined8 FUN_80116460();
extern undefined4 FUN_80119d90();
extern undefined4 FUN_80119fac();
extern undefined4 FUN_80133a68();
extern undefined8 FUN_80133c3c();
extern undefined4 FUN_80134830();
extern undefined4 FUN_801348c0();
extern undefined8 FUN_80134bc4();
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

/*
 * --INFO--
 *
 * Function: FUN_8011a0dc
 * EN v1.0 Address: 0x8011A0DC
 * EN v1.0 Size: 444b
 * EN v1.1 Address: 0x8011A254
 * EN v1.1 Size: 304b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011a0dc(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined param_10)
{
  undefined8 uVar1;
  
  if (param_9 == 0) {
    if (DAT_803dc084 == '\0') {
      FUN_80006824(0,0x100);
      (**(code **)(*DAT_803dd6cc + 8))(0x14,5);
      DAT_803de34f = 0x23;
      DAT_803de34c = 1;
    }
    else {
      uVar1 = FUN_80006824(0,0x419);
      FUN_8011ab20(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
  }
  else {
    DAT_803de34d = 1;
    FUN_80006824(0,0x418);
    (**(code **)(*DAT_803dd6cc + 8))(0x14,1);
    (**(code **)(*DAT_803dd6f0 + 0x1c))(0);
    (**(code **)(*DAT_803dd6f0 + 0x1c))(1);
    (**(code **)(*DAT_803dd6f0 + 0x1c))(2);
    (**(code **)(*DAT_803dd6f0 + 0x1c))(3);
    DAT_803de34f = 0x23;
    DAT_803de344 = param_10;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011a298
 * EN v1.0 Address: 0x8011A298
 * EN v1.0 Size: 656b
 * EN v1.1 Address: 0x8011A384
 * EN v1.1 Size: 420b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011a298(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  int iVar1;
  char cVar2;
  undefined8 uVar3;
  undefined8 extraout_f1;
  
  iVar1 = (int)DAT_803dc65b;
  if (param_9 == 0) {
    if (DAT_803de338 != 0) {
      (**(code **)(*DAT_803dd724 + 0x10))();
      DAT_803de338 = 0;
    }
    uVar3 = FUN_80006824(0,0x419);
    FUN_8011ab20(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  else {
    FUN_80006824(0,0x418);
    if (DAT_803de345 == '\0') {
      if (param_10 == 0) {
        FUN_8011a778();
      }
      else {
        *(ushort *)((&PTR_DAT_8031b40c)[iVar1 * 3] + 0x16) =
             *(ushort *)((&PTR_DAT_8031b40c)[iVar1 * 3] + 0x16) | 0x4000;
        (&PTR_DAT_8031b40c)[iVar1 * 3][0x56] = 0xff;
        *(undefined2 *)((&PTR_DAT_8031b40c)[iVar1 * 3] + 0x3c) = 0x3d8;
        DAT_803de345 = '\x01';
        DAT_803de338 = (**(code **)(*DAT_803dd724 + 0xc))(0x3d7,0x29,0,1,0);
        (**(code **)(*DAT_803dd724 + 0x20))(DAT_803de338,1);
        (**(code **)(*DAT_803dd720 + 0x2c))((&PTR_DAT_8031b40c)[iVar1 * 3]);
      }
    }
    else {
      cVar2 = (**(code **)(*DAT_803dd724 + 0x24))(DAT_803de338);
      if (cVar2 == '\x01') {
        gameplay_applyPreviewSettingsForSlot(extraout_f1,param_2,param_3,param_4,param_5,param_6,
                                             param_7,param_8,DAT_803de324);
      }
      uVar3 = (**(code **)(*DAT_803dd724 + 0x10))(DAT_803de338);
      DAT_803de338 = 0;
      FUN_8011ab20(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011a528
 * EN v1.0 Address: 0x8011A528
 * EN v1.0 Size: 396b
 * EN v1.1 Address: 0x8011A528
 * EN v1.1 Size: 400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011a528(int param_1,char param_2)
{
  DAT_803de330 = DAT_803de328;
  if (param_1 == 0) {
    FUN_80006824(0,0x100);
    (**(code **)(*DAT_803dd6cc + 8))(0x14,5);
    DAT_803de34f = 0x23;
    DAT_803de34c = 1;
  }
  else if ((param_1 != -1) && (param_1 == 1)) {
    DAT_803de324 = param_2;
    if (*(char *)(DAT_803de328 + param_2 * 0x24 + 0x20) == '\0') {
      FUN_80006b84(6);
    }
    else {
      FUN_80006824(0,0x418);
      if (DAT_803dc65b != -1) {
        (**(code **)(*DAT_803dd720 + 8))();
      }
      DAT_803dc65b = '\x01';
      *(ushort *)(PTR_DAT_8031b418 + 0x16) = *(ushort *)(PTR_DAT_8031b418 + 0x16) & 0xbfff;
      PTR_DAT_8031b418[0x56] = 0;
      *(undefined2 *)(PTR_DAT_8031b418 + 0x3c) = 0x3d6;
      DAT_803de345 = 0;
      (**(code **)(*DAT_803dd720 + 4))
                (PTR_DAT_8031b418,DAT_8031b41c,0,0,5,4,0x14,200,0xff,0xff,0xff,0xff);
      (**(code **)(*DAT_803dd720 + 0x18))(0);
      DAT_803de33c = 0;
      DAT_803de33d = 0;
      DAT_803de33e = 0;
      DAT_803de34e = 2;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011a6b4
 * EN v1.0 Address: 0x8011A6B4
 * EN v1.0 Size: 196b
 * EN v1.1 Address: 0x8011A6B8
 * EN v1.1 Size: 216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011a6b4(int *param_1)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar1 = 0;
  iVar2 = 0;
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_1 + 1); iVar3 = iVar3 + 1) {
    DAT_803de330 = DAT_803de328;
    if (*(char *)(DAT_803de328 + iVar1 + 0x20) == '\0') {
      *(undefined2 *)(*param_1 + iVar2) = 0x39d;
      iVar4 = iVar2 + 0x16;
      *(ushort *)(*param_1 + iVar4) = *(ushort *)(*param_1 + iVar4) & 0xfffe;
      *(ushort *)(*param_1 + iVar4) = *(ushort *)(*param_1 + iVar4) | 2;
      *(undefined4 *)(*param_1 + iVar2 + 0x10) = 0xffffffff;
    }
    else {
      *(short *)(*param_1 + iVar2) = (short)iVar3;
      iVar4 = iVar2 + 0x16;
      *(ushort *)(*param_1 + iVar4) = *(ushort *)(*param_1 + iVar4) & 0xfffd;
      *(ushort *)(*param_1 + iVar4) = *(ushort *)(*param_1 + iVar4) | 1;
      *(undefined4 *)(*param_1 + iVar2 + 0x10) = 0xffffffff;
    }
    iVar1 = iVar1 + 0x24;
    iVar2 = iVar2 + 0x3c;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011a778
 * EN v1.0 Address: 0x8011A778
 * EN v1.0 Size: 548b
 * EN v1.1 Address: 0x8011A790
 * EN v1.1 Size: 548b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011a778(void)
{
  int iVar1;
  int iVar2;
  int iVar3;
  
  if (DAT_803dc65b != -1) {
    (**(code **)(*DAT_803dd720 + 8))();
  }
  if ((DAT_803de325 == '\0') && (DAT_803dc084 != '\0')) {
    DAT_803de34d = 1;
    FUN_80006824(0,0x418);
    (**(code **)(*DAT_803dd6cc + 8))(0x14,1);
    (**(code **)(*DAT_803dd6f0 + 0x1c))(0);
    (**(code **)(*DAT_803dd6f0 + 0x1c))(1);
    (**(code **)(*DAT_803dd6f0 + 0x1c))(2);
    (**(code **)(*DAT_803dd6f0 + 0x1c))(3);
    DAT_803de34f = 0x23;
    DAT_803de344 = 0;
  }
  else {
    DAT_803dc65b = '\x04';
    iVar2 = 0;
    iVar1 = 0;
    iVar3 = 6;
    do {
      if ((int)(uint)*(byte *)(DAT_803de330 + DAT_803de324 * 0x24 + 0x21) < iVar2) {
        *(ushort *)(PTR_DAT_8031b43c + iVar1 + 0x16) =
             *(ushort *)(PTR_DAT_8031b43c + iVar1 + 0x16) | 0x4000;
      }
      else {
        *(ushort *)(PTR_DAT_8031b43c + iVar1 + 0x16) =
             *(ushort *)(PTR_DAT_8031b43c + iVar1 + 0x16) & 0xbfff;
      }
      if (((int)(*(byte *)(DAT_803de330 + DAT_803de324 * 0x24 + 0x21) - 1) < iVar2) || (4 < iVar2))
      {
        PTR_DAT_8031b43c[iVar1 + 0x1b] = 0xff;
      }
      else {
        PTR_DAT_8031b43c[iVar1 + 0x1b] = (char)iVar2 + '\x01';
      }
      iVar1 = iVar1 + 0x3c;
      iVar2 = iVar2 + 1;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
    (**(code **)(*DAT_803dd720 + 4))(PTR_DAT_8031b43c,DAT_8031b440,0,&DAT_8031b448,5,4,0,0,0,0,0,0);
    DAT_803de34e = 2;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011a99c
 * EN v1.0 Address: 0x8011A99C
 * EN v1.0 Size: 388b
 * EN v1.1 Address: 0x8011A9B4
 * EN v1.1 Size: 216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011a99c(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar1;
  int iVar2;
  
  DAT_803de330 = DAT_803de328;
  DAT_803dc65c = 0;
  if ((DAT_803dc084 != '\0') &&
     (param_1 = FUN_800e9298(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8),
     DAT_803dc084 != '\0')) {
    DAT_803dc65c = 3;
  }
  iVar2 = DAT_803dc65c * 0x24;
  for (iVar1 = DAT_803dc65c; iVar1 < 3; iVar1 = iVar1 + 1) {
    param_1 = FUN_8028fde8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           DAT_803de330 + iVar2,&DAT_803dc67c,&DAT_803dc680,in_r6,in_r7,in_r8,in_r9,
                           in_r10);
    *(undefined *)(DAT_803de330 + iVar2 + 5) = 0;
    *(undefined *)(DAT_803de330 + iVar2 + 6) = 0;
    *(undefined *)(DAT_803de330 + iVar2 + 4) = 0;
    *(undefined4 *)(DAT_803de330 + iVar2 + 8) = 0;
    *(undefined *)(DAT_803de330 + iVar2 + 0x21) = 0;
    iVar2 = iVar2 + 0x24;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011ab20
 * EN v1.0 Address: 0x8011AB20
 * EN v1.0 Size: 852b
 * EN v1.1 Address: 0x8011AA8C
 * EN v1.1 Size: 304b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011ab20(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  bool bVar1;
  
  if (DAT_803dc65b != -1) {
    param_1 = (**(code **)(*DAT_803dd720 + 8))();
  }
  DAT_803dc65b = 0;
  DAT_803de324 = 0;
  FUN_8011a99c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  FUN_8011a6b4((int *)&PTR_DAT_8031b40c);
  bVar1 = false;
  while (!bVar1) {
    if (DAT_803dc65c == 3) {
      PTR_DAT_8031b40c[0x1a] = 0xff;
    }
    else {
      PTR_DAT_8031b40c[0x1a] = 3;
    }
    bVar1 = true;
  }
  (**(code **)(*DAT_803dd720 + 4))
            (PTR_DAT_8031b40c,DAT_8031b410,0,0,5,4,0x14,200,0xff,0xff,0xff,0xff);
  (**(code **)(*DAT_803dd720 + 0x18))(0);
  DAT_803de34e = 2;
  if (DAT_803dc084 == '\0') {
    FUN_8011a778();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011ae74
 * EN v1.0 Address: 0x8011AE74
 * EN v1.0 Size: 304b
 * EN v1.1 Address: 0x8011ABBC
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011ae74(int param_1)
{
  int iVar1;
  int *piVar2;
  
  if (DAT_8031b454 != 0) {
    FUN_80017814(DAT_8031b454);
    DAT_8031b454 = 0;
  }
  DAT_803de320 = 0;
  if (DAT_803dc65b != -1) {
    (**(code **)(*DAT_803dd720 + 8))();
    DAT_803dc65b = -1;
  }
  if (DAT_803de328 != 0) {
    FUN_80017814(DAT_803de328);
    DAT_803de328 = 0;
  }
  if (DAT_803de32c != 0) {
    FUN_80017814(DAT_803de32c);
    DAT_803de32c = 0;
  }
  iVar1 = 0;
  piVar2 = &DAT_803a92e0;
  do {
    if (*piVar2 != 0) {
      FUN_80053754();
      *piVar2 = 0;
    }
    piVar2 = piVar2 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 4);
  FUN_80053754();
  if (param_1 != 0) {
    FUN_8001767c();
  }
  if (DAT_803de338 != 0) {
    (**(code **)(*DAT_803dd724 + 0x10))();
    DAT_803de338 = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011afa4
 * EN v1.0 Address: 0x8011AFA4
 * EN v1.0 Size: 1584b
 * EN v1.1 Address: 0x8011ACF8
 * EN v1.1 Size: 1028b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011afa4(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  uint uVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  undefined4 in_r6;
  byte bVar7;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar8;
  byte *pbVar9;
  int *piVar10;
  int iVar11;
  ushort *puVar12;
  int iVar13;
  uint uVar14;
  double dVar15;
  undefined8 uVar16;
  double dVar17;
  undefined8 local_38;
  
  uVar3 = FUN_80286830();
  iVar5 = DAT_803dc65b * 0xc;
  FUN_800174d4(FUN_801348c0);
  dVar15 = (double)(**(code **)(*DAT_803dd6cc + 0x18))();
  uVar1 = (uint)((double)lbl_803E29E4 - dVar15);
  if ((uVar1 & 0xff) < 0x80) {
    local_38 = (double)CONCAT44(0x43300000,(uVar1 & 0xff) * 0x86 ^ 0x80000000);
    param_3 = (double)(float)(local_38 - DOUBLE_803e29f8);
    dVar15 = -(double)(float)(param_3 * (double)lbl_803E29F0 - (double)lbl_803E29EC);
    FUN_80134830((double)lbl_803E29E8,dVar15);
    uVar14 = 0;
  }
  else {
    dVar15 = (double)lbl_803E29F4;
    FUN_80134830((double)lbl_803E29E8,dVar15);
    uVar14 = (uVar1 & 0x7f) << 1;
  }
  uVar2 = countLeadingZeros(3 - DAT_803dc65b);
  uVar6 = 0;
  uVar16 = FUN_80133c3c(uVar14,uVar2 >> 5 & 0xff,0);
  bVar7 = (byte)uVar14;
  if (DAT_803dc65b != '\x02') {
    if (DAT_803dc65b < '\x02') {
      if (DAT_803dc65b == '\0') {
        uVar2 = uVar14;
        FUN_80017484(0xff,0xff,0xff,bVar7);
        uVar16 = (**(code **)(*DAT_803dd720 + 0x14))();
        if (DAT_803dc084 != '\0') {
          DAT_803de330 = DAT_803de328;
          iVar4 = 0;
          iVar13 = 0;
          piVar10 = &DAT_803a92b8;
          puVar12 = (ushort *)&DAT_803dc650;
          do {
            FUN_8028fde8(uVar16,dVar15,param_3,param_4,param_5,param_6,param_7,param_8,*piVar10,
                         &DAT_803dc688,(uint)*(byte *)(DAT_803de330 + iVar13 + 4),uVar2,in_r7,in_r8,
                         in_r9,in_r10);
            uVar2 = uVar14;
            FUN_80017484(0xff,0xff,0xff,bVar7);
            uVar16 = FUN_80006c6c((byte *)*piVar10,(uint)*puVar12);
            iVar13 = iVar13 + 0x24;
            piVar10 = piVar10 + 1;
            puVar12 = puVar12 + 1;
            iVar4 = iVar4 + 1;
          } while (iVar4 < 3);
        }
      }
      else if (-1 < DAT_803dc65b) {
        FUN_80119fac(uVar16,dVar15,param_3,param_4,param_5,param_6,param_7,param_8,uVar3,uVar14,
                     uVar6,in_r6,in_r7,in_r8,in_r9,in_r10);
        FUN_80017484(0xff,0xff,0xff,bVar7);
        iVar13 = 0;
        for (iVar4 = DAT_803de330 + DAT_803de324 * 0x24;
            (iVar13 < 3 && (*(int *)(iVar4 + 0xc) != 0)); iVar4 = iVar4 + 4) {
          iVar13 = iVar13 + 1;
        }
        iVar11 = 0x34;
        pbVar9 = &DAT_803dc658 + (3U - iVar13 & 0xff);
        iVar8 = 0;
        for (iVar4 = 0; iVar4 < iVar13; iVar4 = iVar4 + 1) {
          FUN_80017484(0xff,0xff,0xff,bVar7);
          FUN_80006c64(&DAT_803dc684,0x93,0x41,iVar11);
          FUN_80006c6c(*(byte **)(DAT_803de330 + DAT_803de324 * 0x24 + iVar8 + 0xc),(uint)*pbVar9);
          iVar11 = iVar11 + 0x2a;
          pbVar9 = pbVar9 + 1;
          iVar8 = iVar8 + 4;
        }
        if (DAT_803de338 != 0) {
          (**(code **)(*DAT_803dd724 + 0x18))(DAT_803de338,0,uVar14);
        }
      }
    }
    else if (DAT_803dc65b < '\x04') {
      uVar16 = FUN_80017484(0xff,0xff,0xff,bVar7);
      FUN_80006c88(uVar16,dVar15,param_3,param_4,param_5,param_6,param_7,param_8,0x324);
    }
  }
  FUN_80017484(0xff,0xff,0xff,bVar7);
  if (*(short *)(&DAT_8031b412 + iVar5) != -1) {
    if (uVar14 < 0x7f) {
      uVar16 = FUN_80017484(0xff,0xff,0xff,-(char)(uVar14 << 1) - 1);
      FUN_80006c88(uVar16,dVar15,param_3,param_4,param_5,param_6,param_7,param_8,0x331);
    }
    else {
      uVar16 = FUN_80017484(0xff,0xff,0xff,(bVar7 + 0x81) * '\x02');
      FUN_80006c88(uVar16,dVar15,param_3,param_4,param_5,param_6,param_7,param_8,
                   (uint)*(ushort *)(&DAT_8031b412 + iVar5));
    }
  }
  if (*(short *)(&DAT_8031b414 + iVar5) != -1) {
    uVar16 = FUN_80017484(0xff,0xff,0xff,bVar7);
    FUN_80006c88(uVar16,dVar15,param_3,param_4,param_5,param_6,param_7,param_8,
                 (uint)*(ushort *)(&DAT_8031b414 + iVar5));
  }
  (**(code **)(*DAT_803dd720 + 0x30))(uVar1);
  (**(code **)(*DAT_803dd720 + 0x10))(uVar3);
  dVar17 = (double)FUN_800174d4(0);
  FUN_80133a68(dVar17,dVar15,param_3,param_4,param_5,param_6,param_7,param_8,'\0');
  DAT_803de34e = DAT_803de34e + -1;
  if (DAT_803de34e < '\0') {
    DAT_803de34e = '\0';
  }
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011b5d4
 * EN v1.0 Address: 0x8011B5D4
 * EN v1.0 Size: 2732b
 * EN v1.1 Address: 0x8011B0FC
 * EN v1.1 Size: 1340b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8011b5d4(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  byte bVar5;
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  char cVar6;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar7;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  char acStack_28 [32];
  
  cVar6 = DAT_803de34f;
  bVar5 = DAT_803dc070;
  if (3 < DAT_803dc070) {
    bVar5 = 3;
  }
  if ('\0' < DAT_803de34f) {
    DAT_803de34f = DAT_803de34f - bVar5;
  }
  iVar1 = (**(code **)(*DAT_803dd6cc + 0x14))();
  if (iVar1 == 0) {
    (**(code **)(*DAT_803dd720 + 0x34))();
    DAT_803de34e = 4;
  }
  if ((DAT_803de34d == '\0') && (DAT_803de34c == '\0')) {
    if (DAT_803dc65b == '\x03') {
      uVar3 = FUN_80006c00(0);
      if ((uVar3 & 0x100) == 0) {
        if ((uVar3 & 0x200) != 0) {
          (**(code **)(*DAT_803dd6cc + 8))(0x14,5);
          DAT_803de34f = '#';
          DAT_803de34c = '\x01';
        }
      }
      else {
        FUN_8011a778();
      }
    }
    else {
      iVar1 = (**(code **)(*DAT_803dd720 + 0xc))();
      iVar4 = (**(code **)(*DAT_803dd720 + 0x14))();
      uVar7 = extraout_f1_00;
      if (iVar4 != DAT_803de340) {
        uVar7 = FUN_80006824(0,0xfc);
      }
      DAT_803de340 = iVar4;
      if (DAT_803de338 != 0) {
        uVar7 = (**(code **)(*DAT_803dd724 + 0x14))();
      }
      if ((iVar1 != -1) || (DAT_803dc65b == '\0')) {
        cVar6 = (char)iVar4;
        if (DAT_803dc65b == '\x02') {
          if (iVar1 == 0) {
            FUN_80006824(0,0x419);
            DAT_803de324 = cVar6;
            if (DAT_803dc65b != -1) {
              (**(code **)(*DAT_803dd720 + 8))();
            }
            DAT_803dc65b = '\x01';
            *(ushort *)(PTR_DAT_8031b418 + 0x16) = *(ushort *)(PTR_DAT_8031b418 + 0x16) & 0xbfff;
            PTR_DAT_8031b418[0x56] = 0;
            *(undefined2 *)(PTR_DAT_8031b418 + 0x3c) = 0x3d6;
            DAT_803de345 = 0;
            (**(code **)(*DAT_803dd720 + 4))
                      (PTR_DAT_8031b418,DAT_8031b41c,0,0,5,4,0x14,200,0xff,0xff,0xff,0xff);
            (**(code **)(*DAT_803dd720 + 0x18))(0);
            DAT_803de33c = 0;
            DAT_803de33d = 0;
            DAT_803de33e = 0;
            DAT_803de34e = 2;
          }
          else if (iVar1 == 1) {
            DAT_803de34d = '\x01';
            (**(code **)(*DAT_803dd6cc + 8))(0x14,5);
            (**(code **)(*DAT_803dd6f0 + 0x1c))(0);
            (**(code **)(*DAT_803dd6f0 + 0x1c))(1);
            (**(code **)(*DAT_803dd6f0 + 0x1c))(2);
            (**(code **)(*DAT_803dd6f0 + 0x1c))(3);
            DAT_803de34f = '#';
          }
        }
        else if (DAT_803dc65b < '\x02') {
          if (DAT_803dc65b == '\0') {
            FUN_8011a528(iVar1,cVar6);
          }
          else if (-1 < DAT_803dc65b) {
            FUN_8011a298(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,iVar4);
          }
        }
        else if (DAT_803dc65b == '\x04') {
          FUN_8011a0dc(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,cVar6);
        }
      }
    }
    if (DAT_803dc65b == '\x01') {
      FUN_80119d90();
    }
    iVar1 = 0;
  }
  else {
    if (((cVar6 < '\r') || ('\f' < DAT_803de34f)) && (DAT_803de34f < '\x01')) {
      if (DAT_803de34d == '\0') {
        FUN_8011ae74(0);
        DAT_803dc084 = -2;
        FUN_80006b84(4);
      }
      else {
        uVar7 = FUN_80116460();
        if (DAT_803dc084 == '\0') {
          FUN_800e8f58(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        }
        else {
          FUN_800e8ba4(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803de324);
        }
        FUN_8011ae74(1);
        uVar7 = FUN_80134bc4();
        uVar2 = FUN_80017818(0);
        uVar7 = FUN_80043030(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_80017818(uVar2);
        FUN_800067c0((int *)0xbe,0);
        FUN_800067c0((int *)0xc1,0);
        if (DAT_803de344 != 0) {
          FUN_800e8f58(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          (**(code **)(*DAT_803dd72c + 0x78))(1);
          iVar1 = (**(code **)(*DAT_803dd72c + 0x90))();
          *(undefined *)(iVar1 + 0xe) = 0xff;
          uVar7 = extraout_f1;
        }
        if (DAT_803de344 < 2) {
          FUN_80294d64(0);
        }
        else {
          uVar7 = FUN_8028fde8(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                               (int)acStack_28,s__savegame_save_d_bin_8031b4b4,(uint)DAT_803de344,
                               in_r6,in_r7,in_r8,in_r9,in_r10);
          uVar3 = FUN_80006c3c(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                               acStack_28,(int *)0x0,0,in_r6,in_r7,in_r8,in_r9,in_r10);
          if (uVar3 != 0) {
            FUN_80003494(DAT_803de110,uVar3,0x6ec);
            FUN_80017814(uVar3);
          }
        }
        (**(code **)(*DAT_803dd72c + 0x20))();
      }
    }
    iVar1 = (uint)((uint)(int)DAT_803de34f < 0xd) - ((int)DAT_803de34f >> 0x1f);
  }
  return iVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_8011c080
 * EN v1.0 Address: 0x8011C080
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8011B638
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011c080(void)
{
}


/* Trivial 4b 0-arg blr leaves. */
void fn_8011AE20(void) {}
