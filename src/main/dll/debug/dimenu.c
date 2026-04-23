#include "ghidra_import.h"
#include "main/dll/debug/dimenu.h"

extern undefined4 FUN_8000b4f0();
extern undefined4 FUN_8000bb38();
extern undefined8 FUN_80014974();
extern undefined4 FUN_80014b68();
extern undefined4 FUN_800154d0();
extern undefined4 FUN_800168a8();
extern void* FUN_80017400();
extern void* FUN_800195a8();
extern undefined8 FUN_80019940();
extern undefined4 FUN_800199a8();
extern undefined4 FUN_8001b4f8();
extern undefined4 FUN_8001bd8c();
extern undefined4 FUN_800207d0();
extern undefined4 FUN_8002bac4();
extern undefined8 FUN_80054484();
extern undefined4 FUN_80054ed0();
extern undefined4 FUN_800550e0();
extern undefined4 FUN_80055464();
extern undefined4 FUN_8005ced0();
extern undefined4 FUN_8005cf50();
extern undefined4 FUN_8005d06c();
extern undefined4 gameplay_setDebugOptionEnabled();
extern undefined4 gameplay_isDebugOptionEnabled();
extern uint gameplay_hasDebugOption();
extern u8 *gameplay_getPreviewSettings();
extern undefined4 FUN_800e8954();
extern undefined4 FUN_8011c2ac();
extern undefined4 FUN_8011c5fc();
extern int FUN_8011c800();
extern undefined4 FUN_8011c8b0();
extern undefined4 FUN_8011ca98();
extern undefined4 FUN_80134d50();
extern char FUN_80134f44();
extern undefined4 FUN_80134fb0();
extern undefined4 FUN_801350c8();
extern undefined4 FUN_80135ba8();
extern undefined4 FUN_80135e18();
extern uint countLeadingZeros();

extern undefined4 DAT_8031b912;
extern undefined4 DAT_8031b914;
extern undefined4 DAT_8031b930;
extern undefined4 DAT_8031b970;
extern undefined4 DAT_8031b986;
extern undefined4 DAT_8031b9c2;
extern undefined4 DAT_8031b9e8;
extern int DAT_803a9430;
extern undefined4 DAT_803a9434;
extern undefined4 DAT_803a9438;
extern undefined4 DAT_803a943c;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc690;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd720;
extern undefined4* DAT_803dd724;
extern undefined4 DAT_803de378;
extern undefined4 DAT_803de379;
extern undefined4 DAT_803de380;
extern undefined4 DAT_803de384;
extern undefined4 DAT_803de385;
extern undefined4 DAT_803de386;
extern undefined4 DAT_803de388;
extern undefined4 DAT_803de38c;
extern undefined4 DAT_803de390;
extern undefined4 DAT_803de392;
extern undefined4 DAT_803de393;
extern undefined4 DAT_803de394;
extern undefined4 DAT_803de398;
extern undefined4 DAT_803de39c;
extern undefined4 DAT_803de3a0;
extern undefined4 DAT_803de3a8;
extern undefined4 DAT_803de542;
extern f64 DOUBLE_803e2a68;
extern f64 DOUBLE_803e2a78;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e2a54;
extern f32 FLOAT_803e2a58;
extern f32 FLOAT_803e2a5c;
extern f32 FLOAT_803e2a60;
extern f32 FLOAT_803e2a64;
extern f32 FLOAT_803e2a70;
extern undefined4* PTR_DAT_8031b928;

/*
 * --INFO--
 *
 * Function: FUN_8011cd58
 * EN v1.0 Address: 0x8011CD58
 * EN v1.0 Size: 736b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011cd58(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8011d038
 * EN v1.0 Address: 0x8011D038
 * EN v1.0 Size: 552b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011d038(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9)
{
  uint uVar1;
  char cVar4;
  ushort *puVar2;
  undefined *puVar3;
  int iVar5;
  int *piVar6;
  int iVar7;
  double dVar8;
  undefined8 extraout_f1;
  double dVar9;
  undefined8 uVar10;
  double dVar11;
  undefined8 local_18;
  
  iVar7 = DAT_803dc690 * 0x10;
  cVar4 = FUN_80134f44();
  if (cVar4 == '\0') {
    dVar9 = (double)(**(code **)(*DAT_803dd6cc + 0x18))();
    dVar8 = (double)FLOAT_803e2a54;
    FUN_8001b4f8(FUN_80135e18);
    uVar1 = (int)(dVar8 - dVar9) & 0xff;
    if (uVar1 < 0x80) {
      local_18 = (double)CONCAT44(0x43300000,uVar1 * 0x86 ^ 0x80000000);
      param_3 = (double)(float)(local_18 - DOUBLE_803e2a68);
      dVar11 = -(double)(float)(param_3 * (double)FLOAT_803e2a60 - (double)FLOAT_803e2a5c);
      FUN_80135ba8((double)FLOAT_803e2a58,dVar11);
      iVar5 = 0;
    }
    else {
      dVar11 = (double)FLOAT_803e2a64;
      FUN_80135ba8((double)FLOAT_803e2a58,dVar11);
      iVar5 = ((int)(dVar8 - dVar9) & 0x7fU) << 1;
    }
    FUN_801350c8(iVar5,0,0);
    if (*(short *)(&DAT_8031b912 + iVar7) != -1) {
      uVar10 = FUN_80019940(0xff,0xff,0xff,0xff);
      puVar2 = FUN_800195a8(uVar10,dVar11,param_3,param_4,param_5,param_6,param_7,param_8,
                            (uint)*(ushort *)(&DAT_8031b912 + iVar7));
      puVar3 = FUN_80017400((uint)*(byte *)(puVar2 + 2));
      puVar3[0x1e] = (byte)iVar5;
      FUN_800168a8(uVar10,dVar11,param_3,param_4,param_5,param_6,param_7,param_8,
                   (uint)*(ushort *)(&DAT_8031b912 + iVar7));
    }
    if (*(short *)(&DAT_8031b914 + iVar7) != -1) {
      uVar10 = FUN_80019940(0xff,0xff,0xff,(byte)iVar5);
      FUN_800168a8(uVar10,dVar11,param_3,param_4,param_5,param_6,param_7,param_8,
                   (uint)*(ushort *)(&DAT_8031b914 + iVar7));
    }
    iVar7 = 0;
    piVar6 = &DAT_803a9430;
    do {
      if (*piVar6 != 0) {
        (**(code **)(*DAT_803dd724 + 0x18))(*piVar6,param_9,iVar5);
      }
      piVar6 = piVar6 + 1;
      iVar7 = iVar7 + 1;
    } while (iVar7 < 8);
    (**(code **)(*DAT_803dd720 + 0x30))(iVar5);
    (**(code **)(*DAT_803dd720 + 0x10))(param_9);
    dVar8 = (double)FUN_8001b4f8(0);
    FUN_80134fb0(dVar8,dVar11,param_3,param_4,param_5,param_6,param_7,param_8,'\0');
    DAT_803de386 = DAT_803de386 + -1;
    if (DAT_803de386 < '\0') {
      DAT_803de386 = '\0';
    }
  }
  else {
    FUN_80134d50(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011d260
 * EN v1.0 Address: 0x8011D260
 * EN v1.0 Size: 1300b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8011d260(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  char cVar1;
  uint uVar2;
  char cVar7;
  int iVar3;
  int iVar4;
  undefined uVar8;
  undefined4 uVar5;
  int iVar6;
  byte bVar9;
  int *piVar10;
  undefined8 extraout_f1;
  
  cVar1 = DAT_803de384;
  bVar9 = DAT_803dc070;
  cVar7 = FUN_80134f44();
  if (cVar7 == '\0') {
    if (3 < bVar9) {
      bVar9 = 3;
    }
    if ('\0' < DAT_803de384) {
      DAT_803de384 = DAT_803de384 - bVar9;
    }
    iVar3 = (**(code **)(*DAT_803dd6cc + 0x14))();
    if (iVar3 == 0) {
      (**(code **)(*DAT_803dd720 + 0x34))();
      DAT_803de386 = 2;
    }
    if (DAT_803de385 == '\0') {
      iVar3 = (**(code **)(*DAT_803dd720 + 0xc))();
      iVar4 = (**(code **)(*DAT_803dd720 + 0x14))();
      if (iVar4 != DAT_803de380) {
        FUN_8000bb38(0,0xfc);
      }
      DAT_803de380 = iVar4;
      if (DAT_803dc690 == '\x02') {
        FUN_8011c5fc(iVar3,iVar4);
        if (iVar3 == 0) {
          uVar8 = (**(code **)(*DAT_803dd724 + 0x24))(DAT_803a9430);
          *(undefined *)(DAT_803de388 + 6) = uVar8;
          uVar5 = (**(code **)(*DAT_803dd724 + 0x24))(DAT_803a9434);
          uVar2 = countLeadingZeros(uVar5);
          *(char *)(DAT_803de388 + 8) = (char)(uVar2 >> 5);
          FUN_8005ced0(*(char *)(DAT_803de388 + 6));
          FUN_800154d0(*(undefined *)(DAT_803de388 + 8));
        }
      }
      else if (DAT_803dc690 < '\x02') {
        if (DAT_803dc690 == '\0') {
          DAT_803de38c = (undefined)iVar4;
          iVar3 = FUN_8011c800(iVar3,iVar4);
          if (iVar3 != 0) {
            return 0;
          }
        }
        else if ((-1 < DAT_803dc690) && (FUN_8011c2ac(iVar3,iVar4), iVar3 == 0)) {
          uVar8 = (**(code **)(*DAT_803dd724 + 0x24))(DAT_803a9430);
          *(undefined *)(DAT_803de388 + 9) = uVar8;
          uVar8 = (**(code **)(*DAT_803dd724 + 0x24))(DAT_803a9434);
          *(undefined *)(DAT_803de388 + 10) = uVar8;
          uVar8 = (**(code **)(*DAT_803dd724 + 0x24))(DAT_803a9438);
          *(undefined *)(DAT_803de388 + 0xb) = uVar8;
          uVar8 = (**(code **)(*DAT_803dd724 + 0x24))(DAT_803a943c);
          *(undefined *)(DAT_803de388 + 0xc) = uVar8;
        }
      }
      else if (DAT_803dc690 < '\x04') {
        if (iVar3 == 0) {
          FUN_8000bb38(0,0x100);
          (**(code **)(*DAT_803dd6cc + 8))(0x14,5);
          DAT_803de384 = '#';
          DAT_803de385 = '\x01';
        }
        if (((&DAT_803a9430)[iVar4] != 0) &&
           (iVar3 = (**(code **)(*DAT_803dd724 + 0x2c))(), iVar3 != 0)) {
          if (iVar4 == 0) {
            uVar5 = (**(code **)(*DAT_803dd724 + 0x24))(DAT_803a9430);
            uVar2 = countLeadingZeros(uVar5);
            *(char *)(DAT_803de388 + 2) = (char)(uVar2 >> 5);
            FUN_8001bd8c(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (uint)*(byte *)(DAT_803de388 + 2));
          }
          else {
            uVar5 = (**(code **)(*DAT_803dd724 + 0x24))((&DAT_803a9430)[iVar4]);
            uVar2 = countLeadingZeros(uVar5);
            gameplay_setDebugOptionEnabled(3,(char)(uVar2 >> 5));
          }
        }
      }
      if (DAT_803dc690 != '\0') {
        iVar3 = 0;
        piVar10 = &DAT_803a9430;
        do {
          iVar6 = *piVar10;
          if (iVar6 != 0) {
            if (iVar3 == iVar4) {
              (**(code **)(*DAT_803dd724 + 0x20))(iVar6,1);
            }
            else {
              (**(code **)(*DAT_803dd724 + 0x20))(iVar6,0);
            }
            (**(code **)(*DAT_803dd724 + 0x14))(*piVar10);
          }
          piVar10 = piVar10 + 1;
          iVar3 = iVar3 + 1;
        } while (iVar3 < 8);
      }
      iVar3 = 0;
    }
    else {
      if (((cVar1 < '\r') || ('\f' < DAT_803de384)) && (DAT_803de384 < '\x01')) {
        if (DAT_803dc690 != -1) {
          (**(code **)(*DAT_803dd720 + 8))();
          DAT_803dc690 = -1;
        }
        iVar3 = 0;
        piVar10 = &DAT_803a9430;
        do {
          if (*piVar10 != 0) {
            (**(code **)(*DAT_803dd724 + 0x10))();
            *piVar10 = 0;
          }
          piVar10 = piVar10 + 1;
          iVar3 = iVar3 + 1;
        } while (iVar3 < 8);
        FUN_8005cf50(1);
        FUN_8005d06c(1);
        FUN_80014974(4);
      }
      iVar3 = (uint)((uint)(int)DAT_803de384 < 0xd) - ((int)DAT_803de384 >> 0x1f);
    }
  }
  else {
    iVar3 = 0;
  }
  return iVar3;
}

/*
 * --INFO--
 *
 * Function: FUN_8011d774
 * EN v1.0 Address: 0x8011D774
 * EN v1.0 Size: 148b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011d774(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  undefined8 uVar1;
  
  uVar1 = (**(code **)(*DAT_803dd6cc + 0xc))(0x14,5);
  FUN_800199a8(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x15);
  DAT_803de38c = 0;
  DAT_803de388 = (undefined4)gameplay_getPreviewSettings();
  if (DAT_803de378 == '\0') {
    FUN_8011cd58();
  }
  else if (DAT_803de378 == '\x01') {
    FUN_8011ca98();
  }
  else {
    FUN_8011c8b0();
  }
  DAT_803de386 = 2;
  DAT_803de385 = 0;
  DAT_803de379 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011d808
 * EN v1.0 Address: 0x8011D808
 * EN v1.0 Size: 552b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8011d808(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  int iVar2;
  
  if (DAT_803de393 == '\0') {
    iVar1 = (**(code **)(*DAT_803dd720 + 0xc))();
    iVar2 = (**(code **)(*DAT_803dd720 + 0x14))();
    if (iVar1 == 1) {
      if (iVar2 == 0) {
        FUN_8000bb38(0,0x103);
        FUN_80014974(1);
        FUN_800207d0();
        FUN_80014b68(0,0x300);
      }
      else {
        FUN_8000bb38(0,0x104);
        DAT_803de392 = '\0';
        DAT_803de393 = '\x01';
        DAT_8031b986 = DAT_8031b986 | 0x1000;
        DAT_8031b9c2 = DAT_8031b9c2 | 0x1000;
        (**(code **)(*DAT_803dd720 + 0x2c))();
      }
    }
    else if (iVar1 == 0) {
      FUN_8000bb38(0,0x419);
      FUN_80014974(1);
      FUN_800207d0();
      FUN_80014b68(0,0x300);
    }
  }
  else if (DAT_803de393 == '\x01') {
    if (DAT_803de392 == '\0') {
      FUN_800e8954(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
    DAT_803de392 = (char)(int)((float)((double)CONCAT44(0x43300000,(int)DAT_803de392 ^ 0x80000000) -
                                      DOUBLE_803e2a78) + FLOAT_803dc074);
    if (FLOAT_803e2a70 <=
        (float)((double)CONCAT44(0x43300000,(int)DAT_803de392 ^ 0x80000000) - DOUBLE_803e2a78)) {
      DAT_803de393 = '\0';
      DAT_8031b986 = DAT_8031b986 & 0xefff;
      DAT_8031b9c2 = DAT_8031b9c2 & 0xefff;
      (**(code **)(*DAT_803dd720 + 0x2c))();
      (**(code **)(*DAT_803dd720 + 0x18))(0);
    }
  }
  DAT_803de390 = DAT_803de390 + (ushort)DAT_803dc070 * 8;
  if (0x8c < DAT_803de390) {
    DAT_803de390 = 0x8c;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8011da30
 * EN v1.0 Address: 0x8011DA30
 * EN v1.0 Size: 84b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011da30(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  undefined8 uVar1;
  
  FUN_80054484();
  FUN_80054484();
  uVar1 = FUN_80054484();
  FUN_80055464(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,'\x01',param_11,
               param_12,param_13,param_14,param_15,param_16);
  (**(code **)(*DAT_803dd720 + 8))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011da84
 * EN v1.0 Address: 0x8011DA84
 * EN v1.0 Size: 188b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011da84(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8011db40
 * EN v1.0 Address: 0x8011DB40
 * EN v1.0 Size: 116b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8011db40(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
            undefined4 param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  byte bVar1;
  undefined8 uVar2;
  
  FUN_8002bac4();
  bVar1 = DAT_803dc070;
  if (3 < DAT_803dc070) {
    bVar1 = 3;
  }
  if (('\0' < DAT_803de3a8) && (DAT_803de3a8 = DAT_803de3a8 - bVar1, DAT_803de3a8 < '\x01')) {
    uVar2 = FUN_80014974(1);
    FUN_80055464(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x60,'\x01',param_11,
                 param_12,param_13,param_14,param_15,param_16);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8011dbb4
 * EN v1.0 Address: 0x8011DBB4
 * EN v1.0 Size: 72b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011dbb4(void)
{
  FUN_80054484();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011dbfc
 * EN v1.0 Address: 0x8011DBFC
 * EN v1.0 Size: 152b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011dbfc(uint param_1)
{
  ushort uVar1;
  
  uVar1 = 0;
  if (DAT_803de542 == 3) {
    uVar1 = 0x3fc;
  }
  else if (DAT_803de542 < 3) {
    if (DAT_803de542 == 1) {
      uVar1 = 0x3f8;
    }
    else if (DAT_803de542 < 1) {
      if (-1 < DAT_803de542) {
        uVar1 = 0x3fb;
      }
    }
    else {
      uVar1 = 0x3f7;
    }
  }
  else if (DAT_803de542 == 5) {
    uVar1 = 0x3fa;
  }
  else if (DAT_803de542 < 5) {
    uVar1 = 0x3f9;
  }
  if (uVar1 != 0) {
    FUN_8000b4f0(param_1,uVar1,1);
  }
  return;
}
