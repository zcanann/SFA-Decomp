#include "ghidra_import.h"
#include "main/dll/FRONT/dll_39.h"

extern undefined4 FUN_8001406c();
extern undefined4 FUN_80014974();
extern undefined4 FUN_800201ac();
extern undefined4 FUN_80022e1c();
extern undefined4 FUN_800238c4();
extern undefined4 FUN_800238f8();
extern undefined4 FUN_80023d8c();
extern undefined8 FUN_80041f1c();
extern undefined8 FUN_80041f28();
extern undefined4 FUN_80041f34();
extern undefined4 FUN_80043070();
extern undefined4 FUN_80043938();
extern undefined4 FUN_80055464();
extern undefined4 FUN_8007d858();
extern undefined8 FUN_80088e98();
extern undefined8 FUN_8010123c();
extern undefined4 FUN_80117e10();
extern undefined4 FUN_801184a0();
extern undefined4 FUN_80118ac4();
extern undefined4 FUN_80118ba8();
extern bool FUN_80118c08();
extern undefined8 FUN_80118f30();
extern undefined4 FUN_80119154();
extern undefined4 FUN_80119254();
extern int FUN_801192a8();
extern undefined4 FUN_80119594();
extern int FUN_801195e0();
extern undefined8 FUN_8011dc94();
extern int FUN_80241de8();
extern undefined4 FUN_802420b0();
extern undefined4 FUN_80242fc0();
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
extern char s_Fail_to_prepare_8031afec[];
extern char s_n_attractmode_c_8031afdc[];

/*
 * --INFO--
 *
 * Function: FUN_80115ff0
 * EN v1.0 Address: 0x80115FBC
 * EN v1.0 Size: 296b
 * EN v1.1 Address: 0x80115FF0
 * EN v1.1 Size: 288b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80115ff0(void)
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
 * Function: FUN_80116110
 * EN v1.0 Address: 0x801160E4
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x80116110
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80116110(void)
{
  if (DAT_803de268 != '\0') {
    DAT_803de268 = '\0';
    FLOAT_803de26c = FLOAT_803e2980;
    FUN_80014974(4);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8011615c
 * EN v1.0 Address: 0x80116128
 * EN v1.0 Size: 500b
 * EN v1.1 Address: 0x8011615C
 * EN v1.1 Size: 252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011615c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  undefined8 uVar1;
  
  DAT_803de268 = 1;
  FLOAT_803de26c = FLOAT_803e2980;
  FUN_80043938(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar1 = FUN_80041f28();
  FUN_80043070(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x3f);
  uVar1 = FUN_80041f1c();
  uVar1 = FUN_80088e98(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar1 = FUN_8011dc94(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar1 = FUN_8010123c(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  FUN_80055464(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x12,'\0',param_11,
               param_12,param_13,param_14,param_15,param_16);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80116258
 * EN v1.0 Address: 0x8011631C
 * EN v1.0 Size: 264b
 * EN v1.1 Address: 0x80116258
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80116258(void)
{
  byte bVar1;
  
  bVar1 = DAT_803dc070;
  FUN_8007d858();
  if (3 < bVar1) {
    bVar1 = 3;
  }
  if ('\0' < DAT_803de281) {
    DAT_803de281 = DAT_803de281 - bVar1;
  }
  if (DAT_803de280 != '\0') {
    FUN_800201ac(0x44f,0);
    FUN_80014974(4);
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
 * Function: FUN_8011637c
 * EN v1.0 Address: 0x80116424
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x8011637C
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011637c(void)
{
  FUN_8001406c(0);
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
 * Function: FUN_801163b8
 * EN v1.0 Address: 0x80116460
 * EN v1.0 Size: 268b
 * EN v1.1 Address: 0x801163B8
 * EN v1.1 Size: 264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801163b8(void)
{
  undefined4 uVar1;
  
  if (DAT_803de288 == 2) {
    FUN_80118ac4();
    FUN_80119254();
    FUN_80119594();
    uVar1 = FUN_800238f8(0);
    if (DAT_803de2b4 != 0) {
      FUN_800238c4(DAT_803de2b4);
      DAT_803de2b4 = 0;
    }
    if (DAT_803de2b0 != 0) {
      FUN_800238c4(DAT_803de2b0);
      DAT_803de2b0 = 0;
    }
    if (DAT_803de2ac != 0) {
      FUN_800238c4(DAT_803de2ac);
      DAT_803de2ac = 0;
    }
    if (DAT_803de2a8 != 0) {
      FUN_800238c4(DAT_803de2a8);
      DAT_803de2a8 = 0;
    }
    if (DAT_803de2a4 != 0) {
      FUN_800238c4(DAT_803de2a4);
      DAT_803de2a4 = 0;
    }
    if (DAT_803de2a0 != 0) {
      FUN_800238c4(DAT_803de2a0);
      DAT_803de2a0 = 0;
    }
    if (DAT_803de29c != 0) {
      FUN_800238c4(DAT_803de29c);
      DAT_803de29c = 0;
    }
    FUN_800238f8(uVar1);
    DAT_803de288 = 4;
    DAT_803de291 = 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801164c0
 * EN v1.0 Address: 0x8011656C
 * EN v1.0 Size: 1216b
 * EN v1.1 Address: 0x801164C0
 * EN v1.1 Size: 920b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801164c0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  undefined4 uVar2;
  bool bVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar8;
  int local_28;
  int local_24;
  int local_20;
  int local_1c;
  int local_18;
  uint local_14 [3];
  
  DAT_803de291 = 1;
  iVar1 = FUN_801195e0(2);
  if (iVar1 != 0) {
    iVar1 = FUN_801192a8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    if (iVar1 == 0) {
      FUN_80119594();
    }
    else {
      FUN_801184a0(0x803de2b8);
      DAT_803de2c4 = (uint)*(ushort *)(DAT_803dd970 + 4) - DAT_803de2b8 >> 1;
      DAT_803de2c0 = (uint)*(ushort *)(DAT_803dd970 + 6) - iRam803de2bc >> 1;
      FUN_80119154(local_14,&local_18,&local_1c,&local_20,&local_24,&local_28);
      DAT_803de2b4 = FUN_80023d8c(local_14[0],0x18);
      DAT_803de2b0 = FUN_80023d8c(local_18,0x18);
      DAT_803de2ac = FUN_80023d8c(local_1c,0x18);
      DAT_803de2a8 = FUN_80023d8c(local_20,0x18);
      if (local_24 == 0) {
        DAT_803de2a4 = 0;
      }
      else {
        DAT_803de2a4 = FUN_80023d8c(local_24,0x18);
      }
      DAT_803de2a0 = FUN_80023d8c(local_28,0x18);
      DAT_803de29c = FUN_80023d8c(0x4000,0x18);
      if (((((DAT_803de2b4 == 0) || (DAT_803de2b0 == 0)) || (DAT_803de2ac == 0)) ||
          ((DAT_803de2a8 == 0 || ((DAT_803de2a4 == 0 && (local_24 != 0)))))) ||
         ((DAT_803de2a0 == 0 || (DAT_803de29c == 0)))) {
        FUN_80119594();
        uVar2 = FUN_800238f8(0);
        if (DAT_803de2b4 != 0) {
          FUN_800238c4(DAT_803de2b4);
          DAT_803de2b4 = 0;
        }
        if (DAT_803de2b0 != 0) {
          FUN_800238c4(DAT_803de2b0);
          DAT_803de2b0 = 0;
        }
        if (DAT_803de2ac != 0) {
          FUN_800238c4(DAT_803de2ac);
          DAT_803de2ac = 0;
        }
        if (DAT_803de2a8 != 0) {
          FUN_800238c4(DAT_803de2a8);
          DAT_803de2a8 = 0;
        }
        if (DAT_803de2a4 != 0) {
          FUN_800238c4(DAT_803de2a4);
          DAT_803de2a4 = 0;
        }
        if (DAT_803de2a0 != 0) {
          FUN_800238c4(DAT_803de2a0);
          DAT_803de2a0 = 0;
        }
        if (DAT_803de29c != 0) {
          FUN_800238c4(DAT_803de29c);
          DAT_803de29c = 0;
        }
        FUN_800238f8(uVar2);
        FUN_8007d858();
        FUN_80022e1c();
        FUN_80041f34();
        FUN_8007d858();
        FUN_80022e1c();
      }
      else {
        DAT_803de291 = 0;
        FUN_802420b0(DAT_803de2b4,local_14[0]);
        FUN_802420b0(DAT_803de2b0,local_18);
        FUN_802420b0(DAT_803de2ac,local_1c);
        FUN_802420b0(DAT_803de2a8,local_20);
        if (DAT_803de2a4 != 0) {
          FUN_802420b0(DAT_803de2a4,local_24);
        }
        FUN_802420b0(DAT_803de2a0,local_28);
        FUN_802420b0(DAT_803de29c,0x4000);
        uVar4 = DAT_803de2ac;
        uVar5 = DAT_803de2a8;
        uVar6 = DAT_803de2a4;
        uVar7 = DAT_803de2a0;
        uVar8 = FUN_80118f30(DAT_803de2b4,DAT_803de2b0,DAT_803de2ac,DAT_803de2a8,DAT_803de2a4,
                             DAT_803de2a0);
        bVar3 = FUN_80118c08(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,1,uVar4
                             ,uVar5,uVar6,uVar7,in_r9,in_r10);
        if (!bVar3) {
          FUN_80242fc0(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       s_n_attractmode_c_8031afdc,0x33e,s_Fail_to_prepare_8031afec,uVar5,uVar6,uVar7
                       ,in_r9,in_r10);
        }
        FUN_80118ba8();
        DAT_803de288 = 2;
        FUN_8024d054();
        DAT_803de2cd = 10;
        DAT_803de318 = 0;
        if (DAT_803de28c == '\x04') {
          FUN_80117e10(100,1);
        }
        else {
          FUN_80117e10(0,1);
        }
      }
    }
  }
  return;
}
