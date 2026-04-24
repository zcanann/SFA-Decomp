#include "ghidra_import.h"
#include "main/dll/tricky.h"

extern undefined4 FUN_800033a8();
extern undefined4 FUN_80006954();
extern undefined4 FUN_8000695c();
extern undefined4 FUN_80006960();
extern undefined4 FUN_80006984();
extern void* FUN_800069a8();
extern undefined4 FUN_800069d4();
extern double FUN_800069d8();
extern double FUN_800069e4();
extern double FUN_800069f8();
extern undefined4 FUN_80006a00();
extern undefined4 FUN_80006c64();
extern undefined4 FUN_80017484();
extern undefined4 FUN_80017488();
extern undefined4 FUN_80017498();
extern uint FUN_80017690();
extern undefined4 FUN_800176c0();
extern undefined4 FUN_800176c8();
extern int FUN_800176d0();
extern int FUN_80017730();
extern undefined4 FUN_80017814();
extern undefined4 FUN_80017830();
extern int FUN_8001792c();
extern undefined8 FUN_80017964();
extern int FUN_80017a54();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined8 FUN_80017ac8();
extern int FUN_80017ae4();
extern int FUN_80037008();
extern undefined4 FUN_800480a0();
extern undefined4 FUN_800480b4();
extern undefined4 FUN_8004812c();
extern uint FUN_80053078();
extern undefined4 FUN_80053754();
extern undefined4 FUN_8005398c();
extern char FUN_80053be4();
extern int FUN_8005b024();
extern void newshadows_getShadowDiskTexture(int *textureOut);
extern undefined4 FUN_8006f690();
extern undefined4 FUN_8006f8a4();
extern undefined4 FUN_8006f8fc();
extern undefined4 FUN_8006fd90();
extern undefined4 FUN_8007005c();
extern undefined4 FUN_800709d8();
extern undefined4 FUN_800709e0();
extern undefined4 FUN_800709e8();
extern uint FUN_800e6680();
extern undefined4 FUN_80121c4c();
extern undefined8 FUN_801225a8();
extern undefined4 fn_80124A78();
extern undefined4 fn_80124B38();
extern undefined8 FUN_8012c894();
extern undefined4 FUN_802475e4();
extern undefined4 FUN_80247618();
extern undefined4 FUN_8024782c();
extern undefined4 FUN_80247a48();
extern undefined4 FUN_80247a7c();
extern undefined4 FUN_80247d2c();
extern undefined4 FUN_802570dc();
extern undefined4 FUN_80257b5c();
extern undefined4 FUN_80258674();
extern undefined4 FUN_80258944();
extern undefined4 FUN_80259000();
extern undefined4 FUN_80259288();
extern undefined4 FUN_8025a454();
extern undefined4 FUN_8025a5bc();
extern undefined4 FUN_8025a608();
extern undefined4 FUN_8025b94c();
extern undefined4 FUN_8025b9e8();
extern undefined4 FUN_8025bb48();
extern undefined4 FUN_8025bd1c();
extern undefined4 FUN_8025be54();
extern undefined4 FUN_8025be80();
extern undefined4 FUN_8025c1a4();
extern undefined4 FUN_8025c224();
extern undefined4 FUN_8025c2a8();
extern undefined4 FUN_8025c368();
extern undefined4 FUN_8025c428();
extern undefined4 FUN_8025c510();
extern undefined4 FUN_8025c584();
extern undefined4 FUN_8025c5f0();
extern undefined4 FUN_8025c65c();
extern undefined4 FUN_8025c754();
extern undefined4 FUN_8025c828();
extern undefined4 FUN_8025ca04();
extern undefined4 FUN_8025cce8();
extern undefined4 FUN_8025d80c();
extern undefined4 FUN_8025d848();
extern undefined4 FUN_8025d888();
extern undefined4 FUN_8025d8c4();
extern undefined8 FUN_8025da88();
extern undefined4 FUN_8025db38();
extern undefined4 FUN_80286834();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286840();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_8028fde8();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern undefined4 FUN_802949ec();
extern uint FUN_80294be4();
extern int FUN_80294dbc();
extern undefined4 SUB42();

extern undefined4 DAT_802c292c;
extern undefined4 DAT_802c2930;
extern undefined4 DAT_802c2934;
extern undefined4 DAT_802c2938;
extern undefined4 DAT_802c293c;
extern undefined4 DAT_802c2940;
extern undefined4 DAT_8031cbf0;
extern undefined4 DAT_80397480;
extern undefined4 DAT_803a9450;
extern undefined4 DAT_803a9490;
extern undefined4 DAT_803a95b0;
extern undefined4 DAT_803a9610;
extern undefined4 DAT_803a9764;
extern undefined4 DAT_803a9768;
extern undefined4 DAT_803a976c;
extern undefined4 DAT_803a978c;
extern undefined4 DAT_803a9790;
extern undefined4 DAT_803a9794;
extern undefined4 DAT_803a9798;
extern undefined4 DAT_803a97a4;
extern undefined4 DAT_803a9f1c;
extern undefined4 DAT_803a9f24;
extern undefined4 DAT_803a9f28;
extern undefined4 DAT_803a9f40;
extern undefined4 DAT_803a9f44;
extern undefined4 DAT_803a9f48;
extern undefined4 DAT_803a9f4c;
extern undefined4 DAT_803a9f50;
extern undefined4 DAT_803a9f58;
extern undefined4 DAT_803a9f5c;
extern undefined4 DAT_803a9f60;
extern undefined4 DAT_803a9f68;
extern undefined4 DAT_803a9f70;
extern undefined4 DAT_803a9f74;
extern undefined4 DAT_803a9f78;
extern undefined4 DAT_803a9f7c;
extern undefined4 DAT_803a9fc4;
extern undefined4 DAT_803a9fc8;
extern undefined4 DAT_803a9fd0;
extern undefined4 DAT_803a9fd4;
extern undefined4 DAT_803a9fe0;
extern undefined4 DAT_803a9fe8;
extern undefined4 DAT_803a9fec;
extern undefined4 DAT_803a9ff0;
extern undefined4 DAT_803a9ff4;
extern undefined4 DAT_803a9ff8;
extern undefined4 DAT_803a9ffc;
extern undefined4 DAT_803aa000;
extern undefined4 DAT_803aa004;
extern int DAT_803aa040;
extern int DAT_803aa04c;
extern int DAT_803aa070;
extern int DAT_803aa080;
extern undefined4 DAT_803aa088;
extern undefined4 DAT_803aa094;
extern undefined DAT_803b0000;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc084;
extern undefined4 DAT_803dc6c0;
extern undefined4 DAT_803dc6c1;
extern undefined4 DAT_803dc6c2;
extern undefined4 DAT_803dc6d8;
extern undefined4 DAT_803dc6f2;
extern undefined4 DAT_803dc750;
extern undefined4 DAT_803dc754;
extern undefined4 DAT_803dc755;
extern undefined4 DAT_803dc756;
extern undefined4 DAT_803dc757;
extern undefined4 DAT_803dc758;
extern undefined4 DAT_803dc778;
extern undefined4 DAT_803dc780;
extern undefined4 DAT_803dc784;
extern undefined4 DAT_803dc788;
extern undefined4 DAT_803dc78c;
extern undefined4 DAT_803dc790;
extern undefined4 DAT_803dc794;
extern undefined4 DAT_803dc798;
extern undefined4 DAT_803dc79c;
extern undefined4 DAT_803dc7a0;
extern undefined4 DAT_803dc7a8;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803de3b0;
extern undefined4 DAT_803de3c0;
extern undefined4 DAT_803de3da;
extern undefined4 DAT_803de3db;
extern undefined4 DAT_803de3ec;
extern undefined4 DAT_803de3ee;
extern undefined4 DAT_803de3f0;
extern undefined4 DAT_803de3f2;
extern undefined4 DAT_803de3f8;
extern undefined4 DAT_803de400;
extern undefined4 DAT_803de408;
extern undefined4 DAT_803de412;
extern undefined4 DAT_803de413;
extern undefined4 DAT_803de418;
extern undefined4 DAT_803de428;
extern undefined4 DAT_803de42a;
extern undefined4 DAT_803de42c;
extern undefined4 DAT_803de433;
extern undefined4 DAT_803de445;
extern undefined4 DAT_803de44c;
extern undefined4 DAT_803de450;
extern undefined4 DAT_803de458;
extern undefined4 DAT_803de46c;
extern undefined4 DAT_803de478;
extern undefined4 DAT_803de479;
extern undefined4 DAT_803de4b8;
extern undefined4 DAT_803de4dc;
extern undefined4* DAT_803de4e0;
extern undefined4* DAT_803de4e8;
extern undefined4 DAT_803de4f4;
extern undefined4 DAT_803de504;
extern undefined4 DAT_803de50a;
extern undefined4 DAT_803de550;
extern undefined4 DAT_803de55c;
extern undefined4 DAT_803e2aac;
extern undefined4 DAT_803e2ab0;
extern undefined4 DAT_803e2ab4;
extern undefined4 DAT_803e2ab8;
extern undefined4 DAT_cc008000;
extern f64 DOUBLE_803e2af8;
extern f64 DOUBLE_803e2b08;
extern f64 DOUBLE_803e2b20;
extern f64 DOUBLE_803e2b28;
extern f64 DOUBLE_803e2b30;
extern f64 DOUBLE_803e2b38;
extern f64 DOUBLE_803e2b70;
extern f64 DOUBLE_803e2b78;
extern f64 DOUBLE_803e2b80;
extern f64 DOUBLE_803e2ba0;
extern f64 DOUBLE_803e2bb8;
extern f64 DOUBLE_803e2bc0;
extern f64 DOUBLE_803e2bd0;
extern f64 DOUBLE_803e2bd8;
extern f64 DOUBLE_803e2be0;
extern f64 DOUBLE_803e2be8;
extern f64 DOUBLE_803e2bf8;
extern f64 DOUBLE_803e2c00;
extern f64 DOUBLE_803e2c08;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc6f4;
extern f32 FLOAT_803dc74c;
extern f32 FLOAT_803dc75c;
extern f32 FLOAT_803dc760;
extern f32 FLOAT_803dc764;
extern f32 FLOAT_803dc768;
extern f32 FLOAT_803dc76c;
extern f32 FLOAT_803dc770;
extern f32 FLOAT_803dc774;
extern f32 FLOAT_803dc77c;
extern f32 FLOAT_803de3e0;
extern f32 FLOAT_803de3e4;
extern f32 FLOAT_803de470;
extern f32 FLOAT_803de474;
extern f32 FLOAT_803de47c;
extern f32 FLOAT_803de480;
extern f32 FLOAT_803de484;
extern f32 FLOAT_803de488;
extern f32 FLOAT_803de48c;
extern f32 FLOAT_803de490;
extern f32 FLOAT_803de494;
extern f32 FLOAT_803de498;
extern f32 FLOAT_803de4bc;
extern f32 FLOAT_803de4c4;
extern f32 FLOAT_803de4d0;
extern f32 FLOAT_803e2abc;
extern f32 FLOAT_803e2ac0;
extern f32 FLOAT_803e2ac4;
extern f32 FLOAT_803e2ac8;
extern f32 FLOAT_803e2acc;
extern f32 FLOAT_803e2ad0;
extern f32 FLOAT_803e2ad4;
extern f32 FLOAT_803e2ad8;
extern f32 FLOAT_803e2adc;
extern f32 FLOAT_803e2ae0;
extern f32 FLOAT_803e2ae4;
extern f32 FLOAT_803e2ae8;
extern f32 FLOAT_803e2aec;
extern f32 FLOAT_803e2af0;
extern f32 FLOAT_803e2b00;
extern f32 FLOAT_803e2b10;
extern f32 FLOAT_803e2b14;
extern f32 FLOAT_803e2b18;
extern f32 FLOAT_803e2b1c;
extern f32 FLOAT_803e2b40;
extern f32 FLOAT_803e2b44;
extern f32 FLOAT_803e2b4c;
extern f32 FLOAT_803e2b50;
extern f32 FLOAT_803e2b54;
extern f32 FLOAT_803e2b5c;
extern f32 FLOAT_803e2b60;
extern f32 FLOAT_803e2b64;
extern f32 FLOAT_803e2b68;
extern f32 FLOAT_803e2b88;
extern f32 FLOAT_803e2b8c;
extern f32 FLOAT_803e2b90;
extern f32 FLOAT_803e2b94;
extern f32 FLOAT_803e2b98;
extern f32 FLOAT_803e2bb0;
extern f32 FLOAT_803e2bc8;
extern f32 FLOAT_803e2bcc;
extern f32 FLOAT_803e2bf0;
extern f32 FLOAT_803e2c10;
extern f32 FLOAT_803e2c14;
extern f32 FLOAT_803e2c18;
extern f32 FLOAT_803e2c1c;
extern f32 FLOAT_803e2c20;
extern f32 FLOAT_803e2c24;
extern f32 FLOAT_803e2c28;
extern f32 FLOAT_803e2c2c;
extern f32 FLOAT_803e2c30;
extern f32 FLOAT_803e2c34;
extern undefined* PTR_DAT_8031c228;
extern int iRam803de4e4;
extern undefined4* puRam803de4e4;
extern undefined4* puRam803de4ec;
extern char s_x___2f_8031ccf4[];

/*
 * --INFO--
 *
 * Function: FUN_8011d9b0
 * EN v1.0 Address: 0x8011D9B0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8011DC94
 * EN v1.1 Size: 896b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011d9b0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8011d9b4
 * EN v1.0 Address: 0x8011D9B4
 * EN v1.0 Size: 324b
 * EN v1.1 Address: 0x8011E014
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011d9b4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  double dVar1;
  undefined8 uVar2;
  
  FUN_800176c8(1);
  dVar1 = (double)FUN_800176c0(0xff);
  uVar2 = FUN_8012c894(dVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  DAT_803de400 = 0xb;
  DAT_803de55c = FUN_80017498();
  FUN_80017488(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xb);
  FLOAT_803de3e4 = FLOAT_803e2ae0;
  DAT_803de458 = 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011daf8
 * EN v1.0 Address: 0x8011DAF8
 * EN v1.0 Size: 380b
 * EN v1.1 Address: 0x8011E06C
 * EN v1.1 Size: 152b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011daf8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  double extraout_f1;
  undefined8 uVar2;
  
  iVar1 = (**(code **)(*DAT_803dd72c + 0x8c))();
  uVar2 = FUN_8012c894(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  if (*(char *)(iVar1 + 9) == '\0') {
    if (DAT_803dc084 == '\0') {
      DAT_803de400 = 10;
    }
    else {
      DAT_803de400 = 9;
    }
  }
  else {
    DAT_803de400 = 8;
  }
  DAT_803de55c = FUN_80017498();
  FUN_80017488(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xb);
  FLOAT_803de3e4 = FLOAT_803e2ae0;
  DAT_803de458 = 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011dc74
 * EN v1.0 Address: 0x8011DC74
 * EN v1.0 Size: 676b
 * EN v1.1 Address: 0x8011E104
 * EN v1.1 Size: 696b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011dc74(int param_1,undefined param_2,undefined4 param_3,char param_4)
{
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  
  local_10 = DAT_803e2ab8;
  local_c = CONCAT31((int3)((uint)DAT_803e2ab4 >> 8),param_2);
  local_14 = local_c;
  FUN_8025c428(1,(byte *)&local_14);
  FUN_8025d80c((float *)&DAT_803a9490,0);
  FUN_8025d848((float *)&DAT_803a9490,0);
  FUN_8025d888(0);
  FUN_80258944(1);
  FUN_8025be54(0);
  FUN_8025a5bc(0);
  FUN_800480b4(param_1,0);
  FUN_80258674(0,1,4,0x3c,0,0x7d);
  FUN_8025c584(0,0xc);
  local_18 = local_10;
  FUN_8025c510(0,(byte *)&local_18);
  FUN_8025be80(0);
  FUN_8025c828(0,0,0,0xff);
  FUN_8025c1a4(0,2,8,0xe,0xf);
  FUN_8025c224(0,7,1,4,7);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,0,1,0);
  if (*(int *)(param_1 + 0x50) == 0) {
    FUN_8025ca04(1);
  }
  else {
    FUN_8025be80(1);
    FUN_8025c828(1,0,1,0xff);
    FUN_8025c1a4(1,0xf,0xf,0xf,0);
    FUN_8025c224(1,7,1,4,7);
    FUN_8025c65c(1,0,0);
    FUN_8025c2a8(1,0,0,0,1,0);
    FUN_8025c368(1,0,0,0,1,0);
    FUN_8025ca04(2);
  }
  FUN_80259288(0);
  if (param_4 == '\0') {
    FUN_8025cce8(1,4,5,5);
  }
  else {
    FUN_8025cce8(1,4,1,5);
  }
  FUN_8006f8fc(0,7,0);
  FUN_8006f8a4(1);
  FUN_8025c754(7,0,0,7,0);
  FUN_80257b5c();
  FUN_802570dc(9,1);
  FUN_802570dc(0xd,1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011df18
 * EN v1.0 Address: 0x8011DF18
 * EN v1.0 Size: 1340b
 * EN v1.1 Address: 0x8011E3BC
 * EN v1.1 Size: 1464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8011df18(int param_1,int *param_2,int param_3)
{
  int iVar1;
  uint *puVar2;
  uint uVar3;
  double dVar4;
  undefined4 local_100;
  uint local_fc;
  uint local_f8;
  int local_f4;
  float local_f0;
  undefined4 local_ec;
  undefined4 local_e8;
  undefined4 local_e4;
  undefined4 local_e0;
  undefined4 local_dc;
  float afStack_d8 [12];
  float local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  float local_80;
  float local_7c;
  float afStack_78 [2];
  float local_70;
  float local_60;
  float afStack_48 [3];
  float local_3c;
  float local_2c;
  float local_1c;
  
  local_f8 = DAT_803e2ab0;
  local_f0 = DAT_802c292c;
  local_ec = DAT_802c2930;
  local_e8 = DAT_802c2934;
  local_e4 = DAT_802c2938;
  local_e0 = DAT_802c293c;
  local_dc = DAT_802c2940;
  iVar1 = FUN_8001792c(*param_2,param_3);
  puVar2 = (uint *)FUN_800480a0(iVar1,0);
  uVar3 = FUN_80053078(*puVar2);
  FUN_802475e4((float *)&DAT_803a95b0,afStack_48);
  local_3c = FLOAT_803e2abc;
  local_2c = FLOAT_803e2abc;
  local_1c = FLOAT_803e2abc;
  FUN_80247a7c((double)(FLOAT_803e2ae4 / FLOAT_803de48c),(double)(FLOAT_803e2ae4 / FLOAT_803de48c),
               (double)(FLOAT_803e2ae8 / FLOAT_803de48c),afStack_78);
  local_70 = FLOAT_803e2aec / FLOAT_803de48c;
  local_60 = local_70;
  FUN_80247618(afStack_78,afStack_48,afStack_48);
  FUN_8025d8c4(afStack_48,0x1e,1);
  FUN_80258944(3);
  FUN_8025ca04(3);
  FUN_8025be54(2);
  FUN_8025a5bc(1);
  FUN_8025bd1c(0,0,2);
  FUN_8025bb48(0,0,0);
  FUN_8025b9e8(1,&local_f0,'\0');
  FUN_8025b94c(0,0,0,7,1,0,0,0,0,0);
  FUN_8004812c(uVar3,0);
  FUN_80258674(0,1,1,0x1e,0,0x7d);
  FUN_8025c828(0,0,0,4);
  FUN_8025c1a4(0,0xf,0xf,0xf,10);
  FUN_8025c224(0,7,7,7,5);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,0,1,0);
  FUN_8025a608(4,0,0,0,0,0,2);
  local_fc = local_f8;
  FUN_8025a454(4,&local_fc);
  FUN_8025bd1c(1,0,2);
  FUN_8025bb48(1,0,0);
  FUN_8025b94c(1,1,0,7,1,0,0,1,0,0);
  FUN_80247618((float *)&DAT_80397480,(float *)&DAT_803a95b0,afStack_48);
  dVar4 = (double)(FLOAT_803e2af0 * FLOAT_803de4d0 * FLOAT_803de4d0);
  FUN_80247a7c(dVar4,dVar4,(double)FLOAT_803e2ae8,afStack_d8);
  FUN_80247618(afStack_d8,afStack_48,afStack_48);
  dVar4 = (double)(FLOAT_803e2af0 * (float)((double)FLOAT_803e2ae8 - dVar4));
  FUN_80247a48(dVar4,dVar4,(double)FLOAT_803e2abc,afStack_d8);
  FUN_80247618(afStack_d8,afStack_48,afStack_48);
  FUN_8025d8c4(afStack_48,0x21,0);
  FUN_80258674(1,0,0,0x21,0,0x7d);
  FUN_8025c828(1,1,0,0xff);
  FUN_8025c1a4(1,0xf,0xf,0xf,8);
  FUN_8025c224(1,7,7,7,0);
  FUN_8025c65c(1,0,0);
  FUN_8025c2a8(1,0,0,0,1,0);
  FUN_8025c368(1,0,0,0,1,0);
  local_a8 = FLOAT_803dc77c;
  local_a4 = FLOAT_803e2abc;
  local_a0 = FLOAT_803e2abc;
  local_9c = FLOAT_803e2af0;
  local_98 = FLOAT_803e2abc;
  local_94 = FLOAT_803dc77c;
  local_90 = FLOAT_803e2abc;
  local_8c = FLOAT_803e2af0;
  local_88 = FLOAT_803e2abc;
  local_84 = FLOAT_803e2abc;
  local_80 = FLOAT_803e2abc;
  local_7c = FLOAT_803e2ae8;
  FUN_8025d8c4(&local_a8,0x24,1);
  FUN_80258674(2,1,1,0x24,0,0x7d);
  newshadows_getShadowDiskTexture(&local_f4);
  FUN_8004812c(local_f4,1);
  FUN_8025c5f0(2,0x1c);
  local_100 = DAT_803dc778;
  FUN_8025c510(0,(byte *)&local_100);
  FUN_8025be80(2);
  FUN_8025c828(2,2,1,0xff);
  FUN_8025c1a4(2,0xf,0xf,0xf,0);
  FUN_8025c224(2,7,4,6,0);
  FUN_8025c65c(2,0,0);
  FUN_8025c2a8(2,0,0,0,1,0);
  FUN_8025c368(2,1,0,0,1,0);
  if (*(short *)(param_1 + 0x46) == 0x755) {
    FUN_80259288(1);
  }
  else {
    FUN_80259288(2);
  }
  FUN_8025cce8(1,4,5,5);
  FUN_8006f8fc(0,7,0);
  FUN_8006f8a4(1);
  FUN_8025c754(7,0,0,7,0);
  FUN_80257b5c();
  FUN_802570dc(9,1);
  FUN_802570dc(10,1);
  return 1;
}

/*
 * --INFO--
 *
 * Function: FUN_8011e454
 * EN v1.0 Address: 0x8011E454
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8011E974
 * EN v1.1 Size: 584b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011e454(double param_1,double param_2,double param_3,double param_4,int param_5,
                 int param_6,int param_7,int param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8011e458
 * EN v1.0 Address: 0x8011E458
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8011EBBC
 * EN v1.1 Size: 612b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011e458(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 undefined param_5,int param_6,int param_7,int param_8,int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8011e45c
 * EN v1.0 Address: 0x8011E45C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8011EE20
 * EN v1.1 Size: 616b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011e45c(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 undefined param_5,uint param_6,int param_7,int param_8,uint param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8011e460
 * EN v1.0 Address: 0x8011E460
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8011F088
 * EN v1.1 Size: 428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011e460(double param_1,double param_2,int param_3,int param_4,undefined param_5,
                 uint param_6,byte param_7)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8011e464
 * EN v1.0 Address: 0x8011E464
 * EN v1.0 Size: 840b
 * EN v1.1 Address: 0x8011F234
 * EN v1.1 Size: 768b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011e464(double param_1,double param_2,double param_3,double param_4,ushort param_5,
                 ushort param_6,ushort param_7)
{
  double dVar1;
  float afStack_98 [12];
  float afStack_68 [12];
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  
  FLOAT_803de498 = (float)param_1;
  FLOAT_803de494 = (float)param_2;
  FLOAT_803de490 = (float)param_3;
  FLOAT_803de48c = (float)param_4;
  uStack_34 = (uint)param_5;
  local_38 = 0x43300000;
  FLOAT_803de488 =
       (FLOAT_803e2b10 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e2b08)) /
       FLOAT_803e2b14;
  uStack_2c = (uint)param_6;
  local_30 = 0x43300000;
  FLOAT_803de484 =
       (FLOAT_803e2b10 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e2b08)) /
       FLOAT_803e2b14;
  uStack_24 = (uint)param_7;
  local_28 = 0x43300000;
  FLOAT_803de480 =
       (FLOAT_803e2b10 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e2b08)) /
       FLOAT_803e2b14;
  FUN_8024782c((double)FLOAT_803de480,afStack_68,0x79);
  FUN_8024782c((double)FLOAT_803de484,afStack_98,0x78);
  FUN_80247618(afStack_98,afStack_68,afStack_68);
  FUN_8024782c((double)FLOAT_803de488,afStack_98,0x7a);
  FUN_80247618(afStack_98,afStack_68,afStack_68);
  dVar1 = (double)FLOAT_803de48c;
  FUN_80247a7c(dVar1,dVar1,dVar1,afStack_98);
  FUN_80247618(afStack_98,afStack_68,afStack_68);
  FUN_80247a48((double)FLOAT_803de498,(double)FLOAT_803de494,(double)FLOAT_803de490,afStack_98);
  FUN_80247618(afStack_98,afStack_68,(float *)&DAT_803a95b0);
  FUN_80247a7c((double)FLOAT_803dc76c,-(double)FLOAT_803dc770,(double)FLOAT_803dc774,afStack_68);
  FUN_80247a48((double)FLOAT_803e2b18,(double)FLOAT_803e2ae8,(double)FLOAT_803e2abc,afStack_98);
  FUN_80247618(afStack_98,afStack_68,afStack_98);
  FUN_80247618((float *)&DAT_803a95b0,afStack_98,(float *)&DAT_803a9490);
  FUN_80247d2c((double)FLOAT_803dc75c,(double)FLOAT_803dc760,(double)FLOAT_803dc764,
               (double)FLOAT_803dc768,(float *)&DAT_803a9450);
  dVar1 = FUN_800069f8();
  FLOAT_803de47c = (float)dVar1;
  FUN_80006a00((double)FLOAT_803dc75c);
  FUN_800069d4();
  FUN_80006954(1);
  dVar1 = (double)FLOAT_803e2abc;
  FUN_80006960(dVar1,dVar1,dVar1);
  FUN_8000695c(0x8000,0,0);
  FUN_80006984();
  *(float *)(DAT_803de4e0 + 6) = FLOAT_803de498;
  *(float *)(DAT_803de4e0 + 8) = FLOAT_803de494;
  *(float *)(DAT_803de4e0 + 10) = FLOAT_803de490;
  *(float *)(DAT_803de4e0 + 0xc) = FLOAT_803de498;
  *(float *)(DAT_803de4e0 + 0xe) = FLOAT_803de494;
  *(float *)(DAT_803de4e0 + 0x10) = FLOAT_803de490;
  *(float *)(DAT_803de4e0 + 4) = (float)param_4;
  DAT_803de4e0[2] = param_5;
  DAT_803de4e0[1] = param_6;
  *DAT_803de4e0 = param_7;
  *(float *)(puRam803de4e4 + 6) = FLOAT_803de498;
  *(float *)(puRam803de4e4 + 8) = FLOAT_803de494;
  *(float *)(puRam803de4e4 + 10) = FLOAT_803de490;
  *(float *)(puRam803de4e4 + 0xc) = FLOAT_803de498;
  *(float *)(puRam803de4e4 + 0xe) = FLOAT_803de494;
  *(float *)(puRam803de4e4 + 0x10) = FLOAT_803de490;
  *(float *)(puRam803de4e4 + 4) = (float)param_4;
  puRam803de4e4[2] = param_5;
  puRam803de4e4[1] = param_6;
  *puRam803de4e4 = param_7;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011e7ac
 * EN v1.0 Address: 0x8011E7AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8011F534
 * EN v1.1 Size: 244b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011e7ac(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8011e7b0
 * EN v1.0 Address: 0x8011E7B0
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8011F628
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_8011e7b0(void)
{
  return DAT_803de400;
}

/*
 * --INFO--
 *
 * Function: FUN_8011e7bc
 * EN v1.0 Address: 0x8011E7BC
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8011F630
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011e7bc(undefined param_1)
{
  DAT_803de433 = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011e7c8
 * EN v1.0 Address: 0x8011E7C8
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x8011F638
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011e7c8(byte param_1)
{
  DAT_803de44c = param_1 & 1;
  if (param_1 == 3) {
    DAT_803de4b8 = 0xff;
    return;
  }
  if (2 < param_1) {
    return;
  }
  if (param_1 < 2) {
    return;
  }
  DAT_803de4b8 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011e800
 * EN v1.0 Address: 0x8011E800
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8011F670
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011e800(undefined param_1)
{
  DAT_803de412 = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011e80c
 * EN v1.0 Address: 0x8011E80C
 * EN v1.0 Size: 24b
 * EN v1.1 Address: 0x8011F678
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011e80c(void)
{
  DAT_803de504 = 0;
  DAT_803de4f4 = 0xffff;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011e824
 * EN v1.0 Address: 0x8011E824
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x8011F68C
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
short FUN_8011e824(undefined2 *param_1)
{
  if (DAT_803de504 != 0) {
    *param_1 = DAT_803de50a;
  }
  return DAT_803de504;
}

/*
 * --INFO--
 *
 * Function: FUN_8011e844
 * EN v1.0 Address: 0x8011E844
 * EN v1.0 Size: 24b
 * EN v1.1 Address: 0x8011F6AC
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011e844(undefined param_1)
{
  if (DAT_803de42c != '\0') {
    return;
  }
  DAT_803de42c = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011e85c
 * EN v1.0 Address: 0x8011E85C
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8011F6C4
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011e85c(undefined2 param_1)
{
  DAT_803de42a = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011e868
 * EN v1.0 Address: 0x8011E868
 * EN v1.0 Size: 24b
 * EN v1.1 Address: 0x8011F6D0
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011e868(undefined2 param_1)
{
  if (DAT_803de42a != 0) {
    return;
  }
  DAT_803de42a = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011e880
 * EN v1.0 Address: 0x8011E880
 * EN v1.0 Size: 656b
 * EN v1.1 Address: 0x8011F6E8
 * EN v1.1 Size: 720b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011e880(void)
{
  short sVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  undefined4 local_58;
  int local_54;
  int local_50;
  int local_4c;
  int local_48;
  undefined4 local_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  
  uVar5 = (uint)*(ushort *)(DAT_803a9790 + 0xc);
  uVar3 = (uint)DAT_803dc6c1;
  uVar2 = (uint)DAT_803dc6c0;
  uVar4 = *(ushort *)(DAT_803a978c + 10) & 0xff;
  if (DAT_803de3ee == 0) {
    sVar1 = -((ushort)DAT_803dc758 * (ushort)DAT_803dc070);
  }
  else {
    sVar1 = (ushort)DAT_803dc758 * (ushort)DAT_803dc070;
  }
  DAT_803de3ec = DAT_803de3ec + sVar1;
  if (DAT_803de3ec < 0) {
    DAT_803de3ec = 0;
  }
  else if (0xff < DAT_803de3ec) {
    DAT_803de3ec = 0xff;
  }
  if (DAT_803de3ec != 0) {
    FUN_8025db38(&local_48,&local_4c,&local_50,&local_54);
    FUN_8025da88(0,0,0x280,0x1e0);
    uStack_3c = (0x140 - (uint)DAT_803dc6c0) - uVar4 ^ 0x80000000;
    local_40 = 0x43300000;
    FUN_800709e0((double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e2af8),
                 (double)FLOAT_803e2b1c,DAT_803a978c,(int)DAT_803de3ec & 0xff,0x100,uVar4,uVar5,1);
    uStack_34 = 0x140 - DAT_803dc6c1 ^ 0x80000000;
    local_38 = 0x43300000;
    FUN_800709e0((double)(float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e2af8),
                 (double)FLOAT_803e2b1c,DAT_803a9790,(int)DAT_803de3ec & 0xff,0x100,
                 (uint)DAT_803dc6c1 << 1,uVar5,0);
    uStack_2c = 0x140 - DAT_803dc6c0 ^ 0x80000000;
    local_30 = 0x43300000;
    FUN_800709e0((double)(float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e2af8),
                 (double)FLOAT_803e2b1c,DAT_803a9794,(int)DAT_803de3ec & 0xff,0x100,uVar2 - uVar3,
                 uVar5,0);
    uStack_24 = DAT_803dc6c1 + 0x140 ^ 0x80000000;
    local_28 = 0x43300000;
    FUN_800709e0((double)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e2af8),
                 (double)FLOAT_803e2b1c,DAT_803a9794,(int)DAT_803de3ec & 0xff,0x100,uVar2 - uVar3,
                 uVar5,0);
    uStack_1c = DAT_803dc6c0 + 0x140 ^ 0x80000000;
    local_20 = 0x43300000;
    FUN_800709e8((double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e2af8),
                 (double)FLOAT_803e2b1c,DAT_803a978c,(int)DAT_803de3ec & 0xff,0x100);
    local_44 = CONCAT31(0xff0000,(char)DAT_803de3ec);
    local_58 = local_44;
    FUN_8006fd90((DAT_803dc6c2 + 0x140) - (uint)DAT_803dc757,DAT_803dc756 + 0x32,
                 (uint)DAT_803dc757 + DAT_803dc6c2 + 0x140,(uVar5 + 0x32) - (uint)DAT_803dc756,
                 &local_58);
    FUN_8025da88(local_48,local_4c,local_50,local_54);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011eb10
 * EN v1.0 Address: 0x8011EB10
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8011F9B8
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011eb10(ushort param_1)
{
  DAT_803de3ee = param_1 & 0xff;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011eb1c
 * EN v1.0 Address: 0x8011EB1C
 * EN v1.0 Size: 28b
 * EN v1.1 Address: 0x8011F9C4
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011eb1c(undefined param_1,undefined param_2,undefined2 param_3)
{
  DAT_803dc6c0 = param_1;
  DAT_803dc6c1 = param_2;
  DAT_803dc6c2 = param_3;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011eb38
 * EN v1.0 Address: 0x8011EB38
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8011F9D4
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011eb38(undefined param_1)
{
  DAT_803de3da = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011eb44
 * EN v1.0 Address: 0x8011EB44
 * EN v1.0 Size: 116b
 * EN v1.1 Address: 0x8011FA10
 * EN v1.1 Size: 152b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011eb44(void)
{
  uint uVar1;
  int iVar2;
  
  uVar1 = DAT_803de450;
  if (DAT_803de450 != 0) {
    *(undefined *)(DAT_803de450 + 0x18) = 0;
    iVar2 = *(int *)(uVar1 + 0x40);
    if (iVar2 == 1) {
      FUN_80053754();
      FUN_80053754();
      FUN_80053754();
      FUN_80053754();
    }
    else if ((iVar2 < 1) && (-1 < iVar2)) {
      FUN_80053754();
      FUN_80053754();
    }
    FUN_80017814(DAT_803de450);
    DAT_803de450 = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011ebb8
 * EN v1.0 Address: 0x8011EBB8
 * EN v1.0 Size: 1160b
 * EN v1.1 Address: 0x8011FAA8
 * EN v1.1 Size: 1176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011ebb8(void)
{
  byte bVar1;
  int iVar2;
  short sVar3;
  ushort uVar4;
  int iVar5;
  int iVar6;
  char cVar7;
  uint uVar8;
  double dVar9;
  double dVar10;
  int local_78;
  int local_74;
  int local_70;
  int local_6c [3];
  undefined4 local_60;
  uint uStack_5c;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  
  iVar5 = FUN_80017a98();
  iVar2 = DAT_803de450;
  if (DAT_803de450 != 0) {
    bVar1 = *(byte *)(DAT_803de450 + 0x18);
    if ((((*(char *)(DAT_803de450 + 0x44) < '\0') || (DAT_803de400 != '\0')) ||
        (iVar6 = FUN_800176d0(), iVar6 != 0)) ||
       (((iVar5 != 0 && ((*(ushort *)(iVar5 + 0xb0) & 0x1000) != 0)) &&
        (*(short *)(iVar2 + 0x2c) != 0x5d5)))) {
      sVar3 = (ushort)bVar1 + (ushort)DAT_803dc070 * -4;
      if (sVar3 < 0) {
        sVar3 = 0;
      }
      *(char *)(iVar2 + 0x18) = (char)sVar3;
      if ((*(char *)(iVar2 + 0x18) == '\0') && ((char)*(byte *)(iVar2 + 0x44) < '\0')) {
        *(byte *)(iVar2 + 0x44) = *(byte *)(iVar2 + 0x44) & 0x7f;
        FUN_8011eb44();
        return;
      }
    }
    else {
      uVar4 = (ushort)bVar1 + (ushort)DAT_803dc070 * 4;
      if (0xff < uVar4) {
        uVar4 = 0xff;
      }
      *(char *)(iVar2 + 0x18) = (char)uVar4;
    }
    FUN_8025db38(local_6c,&local_70,&local_74,&local_78);
    FUN_8025da88(0,0,0x280,0x1e0);
    iVar5 = *(int *)(iVar2 + 0x40);
    if (iVar5 == 1) {
      uVar4 = *(ushort *)(iVar2 + 0x2c);
      if (uVar4 == 0x643) {
        cVar7 = -0xc;
      }
      else if ((uVar4 < 0x643) && (uVar4 == 0x63e)) {
        cVar7 = -10;
      }
      else {
        cVar7 = '\0';
      }
      uStack_5c = (int)DAT_803de479 + 0xb5U ^ 0x80000000;
      local_60 = 0x43300000;
      local_6c[2] = (0x1a4 - (uint)(*(ushort *)(*(int *)(iVar2 + 0x30) + 0xc) >> 1)) +
                    (int)DAT_803dc754 + (int)cVar7 + (int)DAT_803de478 ^ 0x80000000;
      local_6c[1] = 0x43300000;
      FUN_800709e8((double)(float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,local_6c[2]) - DOUBLE_803e2af8),
                   *(int *)(iVar2 + 0x30),(uint)*(byte *)(iVar2 + 0x18),0x100);
      uVar8 = *(ushort *)(*(int *)(iVar2 + 0x30) + 10) + 0xb4;
      uStack_4c = 0x1a4 - (*(ushort *)(*(int *)(iVar2 + 0x34) + 0xc) >> 1);
      if (*(int *)(iVar2 + 8) < 0x9e) {
        *(uint *)(iVar2 + 8) = *(int *)(iVar2 + 8) + (uint)DAT_803dc070 * (uint)DAT_803dc755;
      }
      iVar5 = *(int *)(iVar2 + 0xc);
      if (iVar5 < 0) {
        iVar5 = 0;
      }
      else if (*(int *)(iVar2 + 8) < iVar5) {
        iVar5 = *(int *)(iVar2 + 8);
      }
      *(int *)(iVar2 + 0xc) = iVar5;
      iVar5 = (int)(short)iVar5;
      uStack_5c = uVar8 + iVar5 ^ 0x80000000;
      local_60 = 0x43300000;
      local_6c[2] = uStack_4c ^ 0x80000000;
      local_6c[1] = 0x43300000;
      FUN_800709e0((double)(float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,local_6c[2]) - DOUBLE_803e2af8),
                   *(undefined4 *)(iVar2 + 0x3c),(uint)*(byte *)(iVar2 + 0x18),0x100,
                   *(int *)(iVar2 + 8) - iVar5,0x1a,0);
      uStack_54 = uVar8 ^ 0x80000000;
      local_58 = 0x43300000;
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      FUN_800709e0((double)(float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e2af8),
                   *(undefined4 *)(iVar2 + 0x38),(uint)*(byte *)(iVar2 + 0x18),0x100,iVar5,0x1a,0);
      uStack_44 = uVar8 + *(int *)(iVar2 + 8) ^ 0x80000000;
      local_48 = 0x43300000;
      uStack_3c = 0x1a4 - (*(ushort *)(*(int *)(iVar2 + 0x34) + 0xc) >> 1) ^ 0x80000000;
      local_40 = 0x43300000;
      FUN_800709e8((double)(float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e2af8),
                   *(int *)(iVar2 + 0x34),(uint)*(byte *)(iVar2 + 0x18),0x100);
    }
    else if ((iVar5 < 1) && (-1 < iVar5)) {
      uVar8 = 0x140 - ((uint)(*(int *)(iVar2 + 0x10) * *(int *)(iVar2 + 4)) >> 1);
      dVar9 = DOUBLE_803e2af8;
      dVar10 = DOUBLE_803e2b08;
      for (iVar5 = 0; iVar5 < *(int *)(iVar2 + 4); iVar5 = iVar5 + 1) {
        if (iVar5 < *(int *)(iVar2 + 0xc)) {
          iVar6 = *(int *)(iVar2 + 0x2c);
        }
        else {
          iVar6 = *(int *)(iVar2 + 0x30);
        }
        local_6c[2] = uVar8 ^ 0x80000000;
        local_6c[1] = 0x43300000;
        uStack_5c = 0x1a4 - *(int *)(iVar2 + 0x14);
        local_60 = 0x43300000;
        FUN_800709e8((double)(float)((double)CONCAT44(0x43300000,local_6c[2]) - dVar9),
                     (double)(float)((double)CONCAT44(0x43300000,uStack_5c) - dVar10),iVar6,
                     (uint)*(byte *)(iVar2 + 0x18),0x100);
        uVar8 = uVar8 + *(int *)(iVar2 + 0x10);
      }
    }
    FUN_8025da88(local_6c[0],local_70,local_74,local_78);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011f040
 * EN v1.0 Address: 0x8011F040
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8011FF40
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011f040(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8011f044
 * EN v1.0 Address: 0x8011F044
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80120028
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011f044(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8011f048
 * EN v1.0 Address: 0x8011F048
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801200F0
 * EN v1.1 Size: 4988b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011f048(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8011f04c
 * EN v1.0 Address: 0x8011F04C
 * EN v1.0 Size: 452b
 * EN v1.1 Address: 0x8012146C
 * EN v1.1 Size: 348b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011f04c(undefined4 param_1,undefined4 *param_2)
{
  float fVar1;
  uint uVar2;
  
  if (-1 < (int)param_2[1]) {
    param_2[1] = param_2[1] - (uint)DAT_803dc070;
    fVar1 = FLOAT_803e2b40;
    if ((int)param_2[1] < 0) {
      FUN_80053754();
      *param_2 = 0;
    }
    else {
      uVar2 = param_2[1] ^ 0x80000000;
      if (FLOAT_803e2c1c <= (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e2af8)) {
        if (FLOAT_803e2b40 != (float)param_2[2]) {
          param_2[2] = FLOAT_803e2c20 *
                       (float)((double)CONCAT44(0x43300000,(uint)DAT_803dc070) - DOUBLE_803e2b08) +
                       (float)param_2[2];
          if (fVar1 < (float)param_2[2]) {
            param_2[2] = fVar1;
          }
        }
      }
      else {
        param_2[2] = (FLOAT_803e2b40 * (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e2af8)
                     ) / FLOAT_803e2c1c;
      }
      FUN_800033a8(-0x7fc55f78,0,0xc);
      DAT_803aa088 = *param_2;
      DAT_803aa094 = 0;
      FUN_800709e8((double)FLOAT_803e2c24,
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803de3c0 + 0xafU ^ 0x80000000) -
                                  DOUBLE_803e2af8),-0x7fc55f78,(int)(float)param_2[2],0x100);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011f210
 * EN v1.0 Address: 0x8011F210
 * EN v1.0 Size: 180b
 * EN v1.1 Address: 0x801215C8
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011f210(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  DAT_803a9ff8 = FUN_8005398c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                              (int)param_9,param_10,param_11,param_12,param_13,param_14,param_15,
                              param_16);
  if (DAT_803a9ff8 != 0) {
    DAT_803aa004 = (undefined2)param_11;
    DAT_803aa000 = FLOAT_803e2abc;
    DAT_803a9ffc = param_10;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011f2c4
 * EN v1.0 Address: 0x8011F2C4
 * EN v1.0 Size: 372b
 * EN v1.1 Address: 0x8012162C
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011f2c4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  undefined **ppuVar1;
  short *psVar2;
  undefined *puVar3;
  undefined4 uVar4;
  undefined8 extraout_f1;
  undefined8 uVar5;
  undefined6 uVar6;
  
  uVar6 = FUN_80286840();
  ppuVar1 = &PTR_DAT_8031c228;
  puVar3 = &DAT_803b0000;
  DAT_803a9ff8 = 0;
  uVar4 = param_11;
  uVar5 = extraout_f1;
  do {
    psVar2 = (short *)*ppuVar1;
    if (psVar2 == (short *)0x0) {
      if (DAT_803a9ff8 != 0) {
        DAT_803aa004 = (undefined2)param_11;
        DAT_803aa000 = FLOAT_803e2abc;
        DAT_803a9ffc = (int)uVar6;
      }
      FUN_8028688c();
      return;
    }
    for (; *psVar2 != -1; psVar2 = psVar2 + 8) {
      if (*psVar2 == (short)((uint6)uVar6 >> 0x20)) {
        DAT_803a9ff8 = FUN_8005398c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                    (int)psVar2[3],puVar3,uVar4,param_12,param_13,param_14,param_15,
                                    param_16);
        break;
      }
    }
    ppuVar1 = ppuVar1 + 4;
  } while( true );
}

/*
 * --INFO--
 *
 * Function: FUN_8011f438
 * EN v1.0 Address: 0x8011F438
 * EN v1.0 Size: 2816b
 * EN v1.1 Address: 0x80121724
 * EN v1.1 Size: 2060b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011f438(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  short sVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  undefined4 uVar6;
  uint uVar7;
  undefined4 in_r10;
  char cVar8;
  uint uVar9;
  double dVar10;
  undefined8 uVar11;
  double dVar12;
  double in_f31;
  double in_ps31_1;
  float local_a8 [4];
  int local_98 [2];
  undefined8 local_90;
  undefined8 local_88;
  longlong local_80;
  longlong local_78;
  longlong local_70;
  longlong local_68;
  longlong local_60;
  longlong local_58;
  longlong local_50;
  longlong local_48;
  longlong local_40;
  longlong local_38;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  FUN_80286834();
  cVar8 = '\0';
  local_98[0] = 0;
  iVar2 = FUN_80017a98();
  iVar3 = FUN_80017a90();
  FUN_8025da88(0,0,0x280,0x1e0);
  dVar10 = (double)FLOAT_803e2abc;
  if ((((dVar10 <= (double)DAT_803a9f4c) || (dVar10 <= (double)DAT_803a9f68)) ||
      (dVar10 <= (double)DAT_803a9f60)) || (DAT_803de418 != 0)) {
    dVar10 = (double)FLOAT_803e2b40;
  }
  dVar12 = (double)FLOAT_803de4c4;
  if (dVar10 <= dVar12) {
    if ((dVar10 < dVar12) &&
       (FLOAT_803de4c4 = -(float)((double)FLOAT_803e2c20 * (double)FLOAT_803dc074 - dVar12),
       FLOAT_803de4c4 < FLOAT_803e2abc)) {
      FLOAT_803de4c4 = FLOAT_803e2abc;
    }
  }
  else {
    FLOAT_803de4c4 = (float)((double)FLOAT_803e2c20 * (double)FLOAT_803dc074 + dVar12);
    if (FLOAT_803e2b40 < FLOAT_803de4c4) {
      FLOAT_803de4c4 = FLOAT_803e2b40;
    }
  }
  uVar7 = (uint)FLOAT_803de4bc;
  local_90 = (double)(longlong)(int)uVar7;
  if ((uVar7 & 0xff) != 0) {
    dVar12 = (double)*(float *)(iVar2 + 0x14);
    iVar4 = FUN_8005b024();
    if ((((DAT_803a9f4c <= FLOAT_803e2c1c) || (FLOAT_803e2c28 <= DAT_803a9f4c)) ||
        (local_90 = (double)(longlong)(int)DAT_803a9f4c, ((int)DAT_803a9f4c & 8U) == 0)) &&
       ((((DAT_803a9f68 <= FLOAT_803e2c1c || (FLOAT_803e2c28 <= DAT_803a9f68)) ||
         (local_90 = (double)(longlong)(int)DAT_803a9f68, ((int)DAT_803a9f68 & 8U) == 0)) &&
        ((iVar4 != 0 || (iVar4 = FUN_80294dbc(iVar2), iVar4 == 0)))))) {
      dVar10 = DOUBLE_803e2af8;
      for (uVar9 = 0; uVar5 = uVar9 & 0xff, (int)uVar5 < DAT_803a9fe0 >> 2; uVar9 = uVar9 + 1) {
        if ((int)uVar5 < (int)DAT_803a9fc4 >> 2) {
          iVar4 = 0x16;
        }
        else if ((int)DAT_803a9fc4 >> 2 < (int)uVar5) {
          iVar4 = 0x12;
        }
        else {
          iVar4 = (DAT_803a9fc4 & 3) + 0x12;
        }
        local_90 = (double)CONCAT44(0x43300000,uVar5 * 0x21 + 0x1e ^ 0x80000000);
        dVar12 = (double)FLOAT_803e2c2c;
        FUN_800709e8((double)(float)(local_90 - dVar10),dVar12,(&DAT_803a9610)[iVar4],uVar7,0x100);
      }
    }
  }
  if ((((uVar7 & 0xff) != 0) && (uVar9 = FUN_80294be4(iVar2), uVar9 != 0)) &&
     (uVar9 = FUN_80017690(0xeb1), uVar9 != 0)) {
    FUN_80121c4c(uVar7,0x100,0);
  }
  iVar2 = 0;
  uVar9 = FUN_800e6680('\x01',0);
  uVar5 = FUN_80017690(0x123);
  if ((uVar5 == 0) && (uVar5 = FUN_80017690(0x83b), uVar5 == 0)) {
    uVar5 = FUN_80017690(0x2e8);
    if ((uVar5 != 0) || (uVar5 = FUN_80017690(0x83c), uVar5 != 0)) {
      iVar2 = 100;
    }
  }
  else {
    iVar2 = 99;
  }
  if (iVar2 != 0) {
    if (uVar9 != 0) {
      sVar1 = 0x104;
    }
    else {
      sVar1 = 0x122;
    }
    local_90 = (double)CONCAT44(0x43300000,(int)sVar1 ^ 0x80000000);
    dVar12 = (double)FLOAT_803e2c2c;
    FUN_800709e8((double)(float)(local_90 - DOUBLE_803e2af8),dVar12,(&DAT_803a9610)[iVar2],uVar7,
                 0x100);
  }
  if (uVar9 != 0) {
    if (iVar2 == 0) {
      sVar1 = 0x122;
    }
    else {
      sVar1 = 0x140;
    }
    local_90 = (double)CONCAT44(0x43300000,(int)sVar1 ^ 0x80000000);
    dVar12 = (double)FLOAT_803e2c2c;
    FUN_800709e8((double)(float)(local_90 - DOUBLE_803e2af8),dVar12,DAT_803a9798,uVar7,0x100);
  }
  if (((uVar7 & 0xff) != 0) && (iVar3 != 0)) {
    cVar8 = '\x16';
    if ((DAT_803a9f70 <= FLOAT_803e2c1c) ||
       ((FLOAT_803e2c28 <= DAT_803a9f70 ||
        (local_90 = (double)(longlong)(int)DAT_803a9f70, ((int)DAT_803a9f70 & 8U) == 0)))) {
      dVar12 = (double)FLOAT_803e2c30;
      FUN_800709e8((double)FLOAT_803e2c1c,dVar12,DAT_803a9764,uVar7,0x100);
    }
    for (uVar9 = 0; (uVar9 & 0xff) < 0x14; uVar9 = uVar9 + 4) {
      uVar5 = uVar9 & 0xff;
      if (((DAT_803a9fe8 & 0xfc) == uVar5) && ((DAT_803a9fe8 & 2) != 0)) {
        iVar2 = (int)(uVar5 * 0xf) >> 2;
        local_90 = (double)CONCAT44(0x43300000,iVar2 + 0x40U ^ 0x80000000);
        FUN_800709e0((double)(float)(local_90 - DOUBLE_803e2af8),(double)FLOAT_803e2c34,DAT_803a976c
                     ,uVar7,0x100,6,0x12,0);
        local_88 = (double)CONCAT44(0x43300000,iVar2 + 0x46U ^ 0x80000000);
        dVar12 = (double)FLOAT_803e2c34;
        FUN_800709d8((double)(float)(local_88 - DOUBLE_803e2af8),dVar12,DAT_803a9768,uVar7,0x100,7,
                     0x12,6,0);
      }
      else {
        if ((int)uVar5 < (int)DAT_803a9fe8) {
          iVar2 = 0x57;
        }
        else {
          iVar2 = 0x56;
        }
        local_88 = (double)CONCAT44(0x43300000,((int)(uVar5 * 0xf) >> 2) + 0x40U ^ 0x80000000);
        dVar12 = (double)FLOAT_803e2c34;
        FUN_800709e8((double)(float)(local_88 - DOUBLE_803e2af8),dVar12,(&DAT_803a9610)[iVar2],uVar7
                     ,0x100);
      }
    }
  }
  iVar2 = (**(code **)(*DAT_803dd6d0 + 0x10))();
  if ((iVar2 < 0x49) && (0x46 < iVar2)) {
    local_88 = (double)CONCAT44(0x43300000,(int)cVar8 + 0x5fU ^ 0x80000000);
    dVar12 = (double)(float)(local_88 - DOUBLE_803e2af8);
    FUN_800709e8((double)FLOAT_803e2c1c,dVar12,DAT_803a97a4,uVar7,0x100);
  }
  uVar11 = FUN_8025da88(0,0,0x280,0x1e0);
  if (DAT_803de3da == '\0') {
    uVar7 = FUN_80017690(0x91b);
    if (uVar7 == 0) {
      uVar7 = FUN_80017690(0x91a);
      if (uVar7 == 0) {
        uVar7 = FUN_80017690(0x919);
        if (uVar7 == 0) {
          sVar1 = 10;
        }
        else {
          sVar1 = 0x32;
        }
      }
      else {
        sVar1 = 100;
      }
    }
    else {
      sVar1 = 200;
    }
    local_88 = (double)(longlong)(int)DAT_803a9f24;
    local_90 = (double)(longlong)(int)DAT_803a9f58;
    uVar11 = FUN_801225a8(uVar11,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,0x1e,
                          (int)(short)DAT_803a9fd0,sVar1,(int)DAT_803a9f24,(int)DAT_803a9f58,
                          local_98,0,in_r10);
    local_80 = (longlong)(int)DAT_803a9f28;
    local_78 = (longlong)(int)DAT_803a9f5c;
    uVar11 = FUN_801225a8(uVar11,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,0x19,
                          (int)(short)DAT_803a9fd4,7,(int)DAT_803a9f28,(int)DAT_803a9f5c,local_98,0,
                          in_r10);
    local_70 = (longlong)(int)DAT_803a9f1c;
    local_68 = (longlong)(int)DAT_803a9f50;
    uVar11 = FUN_801225a8(uVar11,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,0x1a,
                          (int)(short)DAT_803a9fc8,0xf,(int)DAT_803a9f1c,(int)DAT_803a9f50,local_98,
                          0,in_r10);
    local_60 = (longlong)(int)DAT_803a9f40;
    local_58 = (longlong)(int)DAT_803a9f74;
    uVar11 = FUN_801225a8(uVar11,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,0x18,
                          (int)(short)DAT_803a9fec,0x1f,(int)DAT_803a9f40,(int)DAT_803a9f74,local_98
                          ,0,in_r10);
    local_50 = (longlong)(int)DAT_803a9f44;
    local_48 = (longlong)(int)DAT_803a9f78;
    uVar11 = FUN_801225a8(uVar11,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,0x1b,
                          (int)(short)DAT_803a9ff0,7,(int)DAT_803a9f44,(int)DAT_803a9f78,local_98,0,
                          in_r10);
    local_40 = (longlong)(int)DAT_803a9f48;
    local_38 = (longlong)(int)DAT_803a9f7c;
    FUN_801225a8(uVar11,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,0x1c,
                 (int)(short)DAT_803a9ff4,0xff,(int)DAT_803a9f48,(int)DAT_803a9f7c,local_98,0,in_r10
                );
  }
  else {
    local_a8[3] = 0.0;
    local_a8[2] = 0.0;
    local_a8[1] = 0.0;
    local_a8[0] = FLOAT_803e2c18;
    uVar6 = FUN_80017a98();
    iVar2 = FUN_80037008(9,uVar6,local_a8);
    if ((iVar2 != 0) && (DAT_803de400 == '\0')) {
      uVar11 = (**(code **)(**(int **)(iVar2 + 0x68) + 0x54))
                         (iVar2,local_a8 + 3,local_a8 + 2,local_a8 + 1);
      local_98[0] = 0x118;
      FUN_801225a8(uVar11,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,0x1e,
                   (int)(short)(SUB42(local_a8[2],0) - SUB42(local_a8[3],0)),SUB42(local_a8[1],0),
                   0xff,0,local_98,1,in_r10);
    }
  }
  FUN_80286880();
  return;
}
