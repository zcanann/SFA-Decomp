#include "ghidra_import.h"
#include "main/dll/dll_43.h"

extern undefined8 FUN_80015e00();
extern undefined4 FUN_80019940();
extern undefined4 FUN_80077318();
extern undefined4 FUN_8028fde8();

extern undefined4 DAT_803a92e4;
extern undefined4 DAT_803a92e8;
extern undefined4 DAT_803dc66c;
extern undefined4 DAT_803dc674;
extern undefined4 DAT_803de324;
extern undefined4 DAT_803de328;
extern undefined4 DAT_803de330;
extern f32 FLOAT_803e29d8;
extern f32 FLOAT_803e29dc;
extern f32 FLOAT_803e29e0;
extern char s__3d__02d__02d_8031b4a4[];

/*
 * --INFO--
 *
 * Function: FUN_8011a07c
 * EN v1.0 Address: 0x8011A07C
 * EN v1.0 Size: 472b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011a07c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,uint param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  uint uVar2;
  undefined4 uVar3;
  uint uVar4;
  undefined8 uVar5;
  double dVar6;
  undefined auStack_18 [20];
  
  FUN_80077318((double)FLOAT_803e29d8,(double)FLOAT_803e29dc,DAT_803a92e4,param_10,0x100);
  dVar6 = (double)FLOAT_803e29dc;
  FUN_80077318((double)FLOAT_803e29e0,dVar6,DAT_803a92e8,param_10,0x100);
  FUN_80019940(0xff,0xff,0xff,(byte)param_10);
  DAT_803de330 = DAT_803de328;
  uVar3 = 0;
  uVar5 = FUN_80015e00(DAT_803de328 + DAT_803de324 * 0x24,0x41,0,0);
  FUN_8028fde8(uVar5,dVar6,param_3,param_4,param_5,param_6,param_7,param_8,(int)auStack_18,
               &DAT_803dc66c,(uint)*(byte *)(DAT_803de330 + DAT_803de324 * 0x24 + 4),uVar3,param_13,
               param_14,param_15,param_16);
  uVar5 = FUN_80015e00(auStack_18,0x42,0,0);
  uVar2 = *(uint *)(DAT_803de330 + DAT_803de324 * 0x24 + 8);
  uVar4 = uVar2 % 0xe10;
  uVar1 = uVar4 % 0x3c;
  FUN_8028fde8(uVar5,dVar6,param_3,param_4,param_5,param_6,param_7,param_8,(int)auStack_18,
               s__3d__02d__02d_8031b4a4,uVar2 / 0xe10,uVar4 / 0x3c,uVar1,param_14,param_15,param_16)
  ;
  uVar3 = 0;
  uVar5 = FUN_80015e00(auStack_18,0x43,0,0);
  FUN_8028fde8(uVar5,dVar6,param_3,param_4,param_5,param_6,param_7,param_8,(int)auStack_18,
               &DAT_803dc674,(uint)*(byte *)(DAT_803de330 + DAT_803de324 * 0x24 + 6),uVar3,uVar1,
               param_14,param_15,param_16);
  uVar3 = 0;
  uVar5 = FUN_80015e00(auStack_18,0x44,0,0);
  FUN_8028fde8(uVar5,dVar6,param_3,param_4,param_5,param_6,param_7,param_8,(int)auStack_18,
               &DAT_803dc674,(uint)*(byte *)(DAT_803de330 + DAT_803de324 * 0x24 + 5),uVar3,uVar1,
               param_14,param_15,param_16);
  FUN_80015e00(auStack_18,0x45,0,0);
  return;
}
