// Function: FUN_80185dc0
// Entry: 80185dc0
// Size: 348 bytes

/* WARNING: Removing unreachable block (ram,0x80185efc) */
/* WARNING: Removing unreachable block (ram,0x80185dd0) */

void FUN_80185dc0(double param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  float fVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  undefined4 in_r10;
  int iVar6;
  undefined8 uVar7;
  undefined auStack_38 [8];
  undefined4 local_30;
  longlong local_20;
  
  iVar6 = *(int *)(param_9 + 0xb8);
  local_30 = *(undefined4 *)(iVar6 + 8);
  (**(code **)(*DAT_803de750 + 4))(param_9,0xf,0,2,0xffffffff,0);
  uVar3 = 0xffffffff;
  uVar4 = 0;
  iVar5 = *DAT_803de754;
  (**(code **)(iVar5 + 4))(param_9,0,auStack_38,2);
  FUN_8000bb38(param_9,0x71);
  fVar1 = FLOAT_803e46f0;
  *(float *)(param_9 + 0x24) = FLOAT_803e46f0;
  *(float *)(param_9 + 0x2c) = fVar1;
  *(undefined2 *)(iVar6 + 0x10) = 0x32;
  *(undefined2 *)(iVar6 + 0x1a) = 800;
  *(undefined *)(iVar6 + 0x23) = 0;
  *(undefined *)(iVar6 + 0x21) = 0;
  *(undefined4 *)(param_9 + 0xf8) = 0;
  *(undefined4 *)(param_9 + 0xf4) = 2;
  FUN_80036018(param_9);
  uVar7 = FUN_80035f84(param_9);
  *(undefined2 *)(iVar6 + 0x1e) = 0;
  if (param_1 < (double)*(float *)(iVar6 + 8)) {
    iVar2 = FUN_8002bac4();
    FUN_800379bc(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,0x60004,param_9
                 ,0,uVar3,uVar4,iVar5,in_r10);
  }
  local_20 = (longlong)(int)*(float *)(iVar6 + 8);
  FUN_80035c48(param_9,(short)(int)*(float *)(iVar6 + 8),-5,10);
  FUN_80035eec(param_9,0xe,1,0);
  FUN_80036018(param_9);
  return;
}

