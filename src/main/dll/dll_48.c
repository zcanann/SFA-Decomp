#include "ghidra_import.h"
#include "main/dll/dll_48.h"

extern undefined4 FUN_80006c64();
extern undefined4 FUN_80006c88();
extern undefined4 FUN_80017468();
extern undefined8 FUN_80017484();
extern undefined8 FUN_800174d4();
extern undefined4 FUN_80133a68();
extern undefined4 FUN_80133c3c();
extern undefined4 FUN_80134824();
extern undefined4 FUN_80134830();
extern undefined4 FUN_801348bc();
extern undefined4 FUN_801348c0();
extern undefined4 FUN_80293f90();

extern undefined4 DAT_8031b4d0;
extern undefined4 DAT_803a92f0;
extern undefined4 DAT_803de358;
extern undefined4 DAT_803de35c;
extern undefined4 DAT_803de364;
extern undefined1 DAT_803de370;
extern undefined4 DAT_803de374;
extern f64 DOUBLE_803e2a20;
extern f64 DOUBLE_803e2a28;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803de360;
extern f32 FLOAT_803e2a00;
extern f32 FLOAT_803e2a04;
extern f32 FLOAT_803e2a08;
extern f32 FLOAT_803e2a0c;
extern f32 FLOAT_803e2a10;

/*
 * --INFO--
 *
 * Function: FUN_8011b868
 * EN v1.0 Address: 0x8011B868
 * EN v1.0 Size: 960b
 * EN v1.1 Address: 0x8011B8B8
 * EN v1.1 Size: 656b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011b868(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  int iVar2;
  undefined4 extraout_r4;
  undefined4 uVar3;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined1 *puVar4;
  int iVar5;
  undefined8 uVar6;
  double dVar7;
  double dVar8;
  undefined local_68;
  undefined local_67;
  undefined8 local_60;
  undefined8 local_58;
  undefined4 local_50;
  uint uStack_4c;
  longlong local_48;
  undefined4 local_40;
  uint uStack_3c;
  longlong local_38;
  undefined4 local_30;
  uint uStack_2c;
  longlong local_28;
  undefined4 local_20;
  uint uStack_1c;
  longlong local_18;
  
  local_67 = 0;
  FUN_800174d4(FUN_801348bc);
  FUN_80134830((double)FLOAT_803e2a00,(double)FLOAT_803e2a04);
  dVar7 = (double)FLOAT_803de360;
  local_60 = (double)CONCAT44(0x43300000,DAT_803de35c);
  iVar5 = (int)((float)(dVar7 + (double)(float)(local_60 - DOUBLE_803e2a20)) - FLOAT_803e2a08);
  local_58 = (double)(longlong)iVar5;
  FUN_80134824(iVar5,0);
  FUN_80133c3c(0xff,1,1);
  uVar6 = FUN_80017484(0xc0,0xc0,0xc0,0xff);
  FUN_80006c88(uVar6,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,0x3ae);
  FUN_80017484(0xff,0xff,0xff,0xff);
  uVar6 = FUN_800174d4(FUN_801348c0);
  FUN_80006c88(uVar6,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,0xed);
  puVar4 = &DAT_803de370;
  for (iVar5 = 0; iVar5 < (int)(uint)DAT_803de374; iVar5 = iVar5 + 1) {
    local_68 = *puVar4;
    FUN_80006c64(&local_68,iVar5 + 0x2a,0,0);
    puVar4 = puVar4 + 1;
  }
  local_58 = (double)CONCAT44(0x43300000,(uint)DAT_803de358);
  uStack_4c = (uint)((float)(local_58 - DOUBLE_803e2a20) + FLOAT_803dc074);
  local_60 = (double)(longlong)(int)uStack_4c;
  DAT_803de358 = (ushort)uStack_4c;
  uStack_4c = uStack_4c & 0xffff;
  local_50 = 0x43300000;
  dVar7 = (double)FUN_80293f90();
  iVar5 = (int)((double)FLOAT_803e2a10 * dVar7 + (double)FLOAT_803e2a0c);
  local_48 = (longlong)iVar5;
  uStack_3c = (uint)DAT_803de358;
  local_40 = 0x43300000;
  dVar7 = (double)FUN_80293f90();
  iVar1 = (int)((double)FLOAT_803e2a10 * dVar7 + (double)FLOAT_803e2a0c);
  local_38 = (longlong)iVar1;
  uStack_2c = (uint)DAT_803de358;
  local_30 = 0x43300000;
  dVar7 = (double)FUN_80293f90();
  dVar8 = (double)FLOAT_803e2a10;
  iVar2 = (int)(dVar8 * dVar7 + (double)FLOAT_803e2a0c);
  local_28 = (longlong)iVar2;
  uVar3 = 0xff;
  uVar6 = FUN_80017484((byte)iVar2,(byte)iVar1,(byte)iVar5,0xff);
  iVar1 = DAT_803de364;
  uVar3 = FUN_80017468(uVar6,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,
                       (uint)(ushort)(&DAT_8031b4d0)[DAT_803de364],extraout_r4,iVar5,uVar3,in_r7,
                       in_r8,in_r9,in_r10);
  uStack_1c = (&DAT_803a92f0)[iVar1] + 0x8a ^ 0x80000000;
  local_20 = 0x43300000;
  iVar5 = (int)((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e2a28) - FLOAT_803de360);
  local_18 = (longlong)iVar5;
  FUN_80006c64(uVar3,0x56,iVar5,0);
  dVar7 = (double)FUN_800174d4(0);
  FUN_80133a68(dVar7,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,'\0');
  return;
}
