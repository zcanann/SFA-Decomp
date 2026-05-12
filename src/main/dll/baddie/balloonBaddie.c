#include "ghidra_import.h"
#include "main/dll/baddie/balloonBaddie.h"

extern undefined4 FUN_80006954();
extern undefined4 FUN_8000695c();
extern undefined4 FUN_80006960();
extern undefined4 FUN_80006984();
extern undefined4 FUN_80006988();
extern undefined4 FUN_800069a8();
extern undefined4 FUN_800069b0();
extern undefined4 FUN_800069b8();
extern undefined4 FUN_800069bc();
extern undefined4 FUN_800069d4();
extern double FUN_800069f8();
extern undefined4 FUN_80006a00();
extern uint GameBit_Get(int eventId);
extern int FUN_800176d0();
extern int FUN_8001792c();
extern int FUN_80017a54();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined4 FUN_8003b878();
extern int FUN_80042838();
extern undefined4 FUN_80051fc4();
extern undefined4 FUN_80052778();
extern undefined4 FUN_800528d0();
extern undefined4 FUN_80052904();
extern uint FUN_80053078();
extern undefined8 FUN_80053754();
extern int FUN_8005398c();
extern undefined4 FUN_8006f8a4();
extern undefined4 FUN_8006f8fc();
extern undefined4 FUN_800709e8();
extern undefined4 FUN_8011f048();
extern undefined8 FUN_8011f04c();
extern undefined4 FUN_8025c754();
extern undefined4 FUN_8025cce8();
extern undefined4 FUN_8025da64();
extern undefined4 FUN_8025da88();
extern undefined8 FUN_8028682c();
extern undefined4 FUN_80286878();
extern undefined4 FUN_80294964();

extern undefined4 DAT_8031c130;
extern undefined4 DAT_8031c268;
extern undefined4 DAT_803a9450;
extern undefined4 DAT_803a9684;
extern undefined1 DAT_803a9898;
extern undefined4 DAT_803a98d8;
extern undefined4 DAT_803a9918;
extern undefined4 DAT_803a9958;
extern short DAT_803a9998;
extern short DAT_803a9a18;
extern undefined4 DAT_803a9a98;
extern undefined4 DAT_803a9b98;
extern int DAT_803a9c98;
extern short DAT_803a9d98;
extern int DAT_803a9e18;
extern undefined4 DAT_803a9ff8;
extern undefined4 DAT_803aa008;
extern undefined4 DAT_803aa024;
extern undefined4* DAT_803aa040;
extern undefined4* DAT_803aa044;
extern undefined4* DAT_803aa048;
extern undefined4* DAT_803aa04c;
extern undefined4* DAT_803aa050;
extern undefined4* DAT_803aa054;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc698;
extern undefined4 DAT_803dc6cd;
extern undefined4 DAT_803dc6ce;
extern undefined4* DAT_803dd6d0;
extern undefined4 DAT_803dd970;
extern undefined4 DAT_803de3b8;
extern undefined4 DAT_803de3bc;
extern undefined4 DAT_803de400;
extern undefined4 DAT_803de40e;
extern undefined4 DAT_803de415;
extern undefined4 DAT_803de416;
extern undefined4 DAT_803de418;
extern undefined4 DAT_803de41a;
extern undefined4 DAT_803de41c;
extern undefined4 DAT_803de41e;
extern undefined4 DAT_803de454;
extern undefined4 DAT_803de460;
extern undefined4 DAT_803de4b0;
extern undefined4 DAT_803de4b4;
extern undefined4 DAT_803de4f4;
extern undefined4 DAT_803de504;
extern undefined4 DAT_803de50a;
extern undefined4 DAT_803de514;
extern undefined4 DAT_803de516;
extern undefined4 DAT_803de536;
extern undefined4 DAT_803de537;
extern undefined4 DAT_803de554;
extern undefined4 DAT_803de556;
extern undefined4 DAT_803e2a90;
extern undefined4 DAT_803e2a94;
extern f64 DOUBLE_803e2af8;
extern f64 DOUBLE_803e2b08;
extern f64 DOUBLE_803e2ca8;
extern f64 DOUBLE_803e2cb0;
extern f32 FLOAT_803dc70c;
extern f32 FLOAT_803dc72c;
extern f32 FLOAT_803dc730;
extern f32 FLOAT_803e2abc;
extern f32 FLOAT_803e2ac0;
extern f32 FLOAT_803e2ae8;
extern f32 FLOAT_803e2b44;
extern f32 FLOAT_803e2bb4;
extern f32 FLOAT_803e2c90;
extern f32 FLOAT_803e2c98;
extern f32 FLOAT_803e2c9c;
extern f32 FLOAT_803e2ca0;
extern f32 FLOAT_803e2ca4;
extern f32 FLOAT_803e2cb8;
extern f32 FLOAT_803e2cbc;

/*
 * --INFO--
 *
 * Function: FUN_801242dc
 * EN v1.0 Address: 0x801242DC
 * EN v1.0 Size: 192b
 * EN v1.1 Address: 0x8012434C
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801242dc(void)
{
  if (DAT_803dc6cd < '\0') {
    DAT_803de416 = DAT_803de416 + (ushort)DAT_803dc070 * -(short)DAT_803dc6cd;
    if (0 < DAT_803de416) {
      DAT_803de416 = 0;
      DAT_803dc6cd = '\0';
      DAT_803de40e = 0;
    }
  }
  else {
    DAT_803de416 = DAT_803de416 - (ushort)DAT_803dc070 * (short)DAT_803dc6cd;
    if (DAT_803de416 < 0) {
      DAT_803de416 = 0;
      DAT_803dc6cd = '\0';
      DAT_803de40e = 0;
    }
  }
  if (DAT_803de415 == '\0') {
    if ((DAT_803de556 == 0) &&
       (DAT_803de418 = DAT_803de418 + (ushort)DAT_803dc070 * -8, DAT_803de418 < 0)) {
      DAT_803de418 = 0;
    }
  }
  else {
    DAT_803de418 = DAT_803de418 + (ushort)DAT_803dc070 * 8;
    if (0xff < DAT_803de418) {
      DAT_803de418 = 0xff;
    }
  }
  if ((DAT_803de415 == '\0') || (DAT_803de418 < 0x41)) {
    DAT_803de556 = DAT_803de556 + (ushort)DAT_803dc070 * -0x10;
    if (DAT_803de556 < 0) {
      DAT_803de556 = 0;
    }
  }
  else {
    DAT_803de556 = DAT_803de556 + (ushort)DAT_803dc070 * 0x10;
    if (DAT_803dc6ce < DAT_803de556) {
      DAT_803de556 = DAT_803dc6ce;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: fn_801244B0
 * EN v1.0 Address: 0x8012439C
 * EN v1.0 Size: 264b
 * EN v1.1 Address: 0x801244B0
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int fn_801244B0(short *param_1,char param_2)
{
  uint uVar1;
  int iVar2;
  short *psVar3;
  
  iVar2 = 0;
  psVar3 = param_1;
  if (param_2 == '\0') {
    for (; -1 < *psVar3; psVar3 = psVar3 + 8) {
      uVar1 = GameBit_Get((int)*psVar3);
      if (uVar1 != 0) {
        if (param_1 == (short *)&DAT_8031c130) {
          if ((psVar3[2] < 0) || (uVar1 = GameBit_Get((int)psVar3[2]), uVar1 == 0)) {
            iVar2 = iVar2 + 1;
          }
        }
        else if (((psVar3[1] < 0) || (uVar1 = GameBit_Get((int)psVar3[1]), uVar1 == 0)) &&
                ((psVar3[2] < 0 || (uVar1 = GameBit_Get((int)psVar3[2]), uVar1 == 0)))) {
          iVar2 = iVar2 + 1;
        }
      }
    }
  }
  else if (0 < (int)DAT_803de3b8) {
    for (; -1 < *param_1; param_1 = param_1 + 8) {
      if ((DAT_803de3b8 != 0xffffffff) && ((DAT_803de3b8 & (int)*param_1) != 0)) {
        iVar2 = iVar2 + 1;
      }
    }
  }
  return iVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_801244a4
 * EN v1.0 Address: 0x801244A4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801245C0
 * EN v1.1 Size: 1208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801244a4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: fn_80124A78
 * EN v1.0 Address: 0x801244A8
 * EN v1.0 Size: 200b
 * EN v1.1 Address: 0x80124A78
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 fn_80124A78(int param_1,int *param_2,int param_3)
{
  int iVar1;
  uint uVar2;
  uint uVar3;
  
  uVar3 = DAT_803e2a94;
  iVar1 = FUN_8001792c(*param_2,param_3);
  FUN_80052904();
  uVar3 = CONCAT31(uVar3 >> 8,*(undefined *)(param_1 + 0x37));
  uVar2 = FUN_80053078(*(uint *)(iVar1 + 0x24));
  FUN_80051fc4(uVar2,0,0,(char *)&uVar3,0,1);
  FUN_800528d0();
  FUN_8025cce8(1,4,5,5);
  FUN_8006f8fc(0,7,0);
  FUN_8006f8a4(0);
  FUN_8025c754(7,0,0,7,0);
  return 1;
}

/*
 * --INFO--
 *
 * Function: fn_80124B38
 * EN v1.0 Address: 0x80124570
 * EN v1.0 Size: 348b
 * EN v1.1 Address: 0x80124B38
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 fn_80124B38(int param_1,int *param_2,int param_3)
{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint *puVar4;
  uint *puVar5;
  
  uVar3 = DAT_803e2a90;
  iVar2 = FUN_8001792c(*param_2,param_3);
  iVar2 = *(byte *)(iVar2 + 0x29) - 1;
  FUN_80052904();
  if ((-1 < iVar2) && (iVar2 < 7)) {
    puVar4 = &DAT_803aa024;
    puVar5 = &DAT_803aa008;
    if (puVar4[iVar2] != 0) {
      if (puVar5[iVar2] == 0) {
        iVar1 = (int)(FLOAT_803e2c90 *
                     (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x37)) -
                            DOUBLE_803e2b08));
        uVar3 = CONCAT31(uVar3 >> 8,(undefined)iVar1);
      }
      else {
        uVar3 = CONCAT31(uVar3 >> 8,*(undefined *)(param_1 + 0x37));
      }
      FUN_80051fc4(puVar4[iVar2],0,0,(char *)&uVar3,0,1);
    }
    else {
      FUN_80052778((char *)&uVar3 + 1);
    }
  }
  else {
    FUN_80052778((char *)&uVar3 + 1);
  }
  FUN_800528d0();
  FUN_8025cce8(1,4,5,5);
  FUN_8006f8fc(0,7,0);
  FUN_8006f8a4(0);
  FUN_8025c754(7,0,0,7,0);
  return 1;
}

/*
 * --INFO--
 *
 * Function: FUN_801246cc
 * EN v1.0 Address: 0x801246CC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80124C7C
 * EN v1.1 Size: 1000b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801246cc(undefined4 param_1,undefined4 param_2,undefined4 param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801246d0
 * EN v1.0 Address: 0x801246D0
 * EN v1.0 Size: 748b
 * EN v1.1 Address: 0x80125064
 * EN v1.1 Size: 1220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801246d0(void)
{
  short sVar2;
  short sVar3;
  int iVar1;
  short sVar4;
  int iVar5;
  undefined8 local_10;
  
  sVar2 = DAT_803de41a * (ushort)DAT_803dc070 * 1000;
  iVar5 = (int)sVar2;
  if (iVar5 != 0) {
    sVar3 = DAT_803de41c - DAT_803de41e;
    if (0x8000 < sVar3) {
      sVar3 = sVar3 + 1;
    }
    if (sVar3 < -0x8000) {
      sVar3 = sVar3 + -1;
    }
    if (iVar5 < 0) {
      iVar5 = -iVar5;
    }
    iVar1 = (int)sVar3;
    if (iVar1 < 0) {
      iVar1 = -iVar1;
    }
    if (iVar5 < iVar1) {
      DAT_803de41c = DAT_803de41c + sVar2;
    }
    else {
      DAT_803de41c = DAT_803de41e;
      DAT_803de41a = 0;
    }
    sVar2 = DAT_803de41c;
    sVar3 = DAT_803de41c - DAT_803de41e;
    if (0x8000 < sVar3) {
      sVar3 = sVar3 + 1;
    }
    if (sVar3 < -0x8000) {
      sVar3 = sVar3 + -1;
    }
    iVar5 = (int)sVar3;
    if (iVar5 < 0) {
      iVar5 = -iVar5;
    }
    if (iVar5 < 0x2aab) {
      DAT_803de536 = DAT_803de537;
    }
    *DAT_803aa04c = DAT_803de41c;
    *DAT_803aa040 = sVar2;
    *DAT_803aa050 = sVar2 + 0x5555;
    *DAT_803aa044 = sVar2 + 0x5555;
    *DAT_803aa054 = sVar2 + -0x5556;
    *DAT_803aa048 = sVar2 + -0x5556;
  }
  sVar2 = DAT_803de41c;
  *DAT_803aa04c = DAT_803de41c;
  *DAT_803aa040 = sVar2;
  *DAT_803aa050 = sVar2 + 0x5555;
  *DAT_803aa044 = sVar2 + 0x5555;
  *DAT_803aa054 = sVar2 + -0x5556;
  *DAT_803aa048 = sVar2 + -0x5556;
  sVar2 = DAT_803de41c;
  if (0x8000 < DAT_803de41c) {
    sVar2 = DAT_803de41c + 1;
  }
  if (sVar2 < -0x8000) {
    sVar2 = sVar2 + -1;
  }
  sVar3 = DAT_803de41c + -0x5555;
  if (0x8000 < sVar3) {
    sVar3 = DAT_803de41c + -0x5554;
  }
  if (sVar3 < -0x8000) {
    sVar3 = sVar3 + -1;
  }
  sVar4 = DAT_803de41c + 0x5556;
  if (0x8000 < sVar4) {
    sVar4 = DAT_803de41c + 0x5557;
  }
  if (sVar4 < -0x8000) {
    sVar4 = sVar4 + -1;
  }
  iVar5 = (int)sVar3;
  if (iVar5 < 0) {
    iVar5 = -iVar5;
  }
  iVar1 = (int)sVar2;
  if (iVar1 < 0) {
    iVar1 = -iVar1;
  }
  if (iVar1 < iVar5) {
    sVar3 = sVar2;
    if (sVar2 < 0) {
      sVar3 = -sVar2;
    }
  }
  else if (sVar3 < 0) {
    sVar3 = -sVar3;
  }
  iVar5 = (int)sVar4;
  if (iVar5 < 0) {
    iVar5 = -iVar5;
  }
  if ((iVar5 <= sVar3) && (sVar3 = sVar4, sVar4 < 0)) {
    sVar3 = -sVar4;
  }
  local_10 = (double)CONCAT44(0x43300000,(int)sVar3 ^ 0x80000000);
  sVar2 = (short)(int)-(DOUBLE_803e2cb0 * (local_10 - DOUBLE_803e2af8) - DOUBLE_803e2ca8);
  if (sVar2 < 1) {
    sVar2 = 0;
  }
  DAT_803de554 = (char)sVar2;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801249bc
 * EN v1.0 Address: 0x801249BC
 * EN v1.0 Size: 704b
 * EN v1.1 Address: 0x80125528
 * EN v1.1 Size: 480b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801249bc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int extraout_r4;
  int extraout_r4_00;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar6;
  int local_18 [3];
  
  iVar1 = FUN_80017a98();
  iVar2 = FUN_80017a90();
  uVar4 = 0x280;
  uVar5 = 0x1e0;
  FUN_8025da88(0,0,0x280,0x1e0);
  uVar6 = FUN_8011f04c(param_9,&DAT_803a9ff8);
  if (iVar2 == 0) {
    DAT_803de3b8 = 0;
    DAT_803de3bc = 0;
  }
  else {
    DAT_803de3b8 = (**(code **)(**(int **)(iVar2 + 0x68) + 0x24))(iVar2);
    uVar6 = (**(code **)(**(int **)(iVar2 + 0x68) + 0x20))(iVar2);
    DAT_803de3bc = (undefined4)((ulonglong)uVar6 >> 0x20);
  }
  FUN_8011f048((int)((ulonglong)uVar6 >> 0x20),(int)uVar6,uVar4,uVar5,in_r7,in_r8,in_r9,in_r10);
  iVar3 = (**(code **)(*DAT_803dd6d0 + 0x10))();
  if ((((iVar3 != 0x44) && ((*(ushort *)(iVar1 + 0xb0) & 0x1000) == 0)) && (DAT_803de400 == '\0'))
     && ((iVar2 != 0 && (iVar1 = FUN_800176d0(), iVar1 == 0)))) {
    iVar3 = **(int **)(iVar2 + 0x68);
    uVar6 = (**(code **)(iVar3 + 0x48))(iVar2,local_18);
    iVar1 = extraout_r4;
    if ((DAT_803de4b4 != 0) && (iVar1 = (int)DAT_803de4b0, iVar1 != local_18[0])) {
      uVar6 = FUN_80053754();
      DAT_803de4b0 = -1;
      DAT_803de4b4 = 0;
      iVar1 = extraout_r4_00;
    }
    if (((DAT_803de4b4 == 0) && (-1 < local_18[0])) &&
       (*(short *)(&DAT_8031c268 + local_18[0] * 2) != -1)) {
      DAT_803de4b4 = FUN_8005398c(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                  (int)*(short *)(&DAT_8031c268 + local_18[0] * 2),iVar1,iVar3,uVar5
                                  ,in_r7,in_r8,in_r9,in_r10);
    }
    DAT_803de4b0 = (short)local_18[0];
    if (DAT_803de4b4 != 0) {
      FUN_800709e8((double)FLOAT_803e2c98,(double)FLOAT_803e2cb8,DAT_803a9684,0xff,0x100);
      FUN_800709e8((double)FLOAT_803e2c98,(double)FLOAT_803e2cbc,DAT_803de4b4,0xff,0x80);
    }
  }
  return;
}
