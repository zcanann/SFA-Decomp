// Function: FUN_801e51cc
// Entry: 801e51cc
// Size: 644 bytes

void FUN_801e51cc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,undefined4 param_10,undefined4 param_11,int param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  int local_18;
  int local_14 [2];
  
  piVar4 = *(int **)(param_9 + 0xb8);
  *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
  if (*piVar4 == 0) {
    iVar1 = FUN_8002e1f4(&local_18,local_14);
    for (local_18 = 0; local_18 < local_14[0]; local_18 = local_18 + 1) {
      iVar3 = *(int *)(iVar1 + local_18 * 4);
      if (*(short *)(iVar3 + 0x46) == 0x121) {
        *piVar4 = iVar3;
        FUN_80037e24(param_9,*piVar4,1);
        local_18 = local_14[0];
      }
    }
  }
  if (((*(byte *)(param_9 + 0xaf) & 4) == 0) || (uVar2 = FUN_80020078(0x92a), uVar2 != 0)) {
    if ((*(byte *)(param_9 + 0xaf) & 1) != 0) {
      FUN_80014b68(0,0x100);
      (**(code **)(*DAT_803dd6d4 + 0x84))(param_9,0);
      if (*(char *)((int)piVar4 + 5) == '\0') {
        param_12 = *DAT_803dd6d4;
        (**(code **)(param_12 + 0x48))(1,param_9,0xffffffff);
        *(undefined *)((int)piVar4 + 5) = 1;
      }
      else {
        param_12 = *DAT_803dd6d4;
        (**(code **)(param_12 + 0x48))(2,param_9,0xffffffff);
      }
    }
    if (*(int *)(param_9 + 0x30) != 0) {
      iVar3 = *(int *)(*(int *)(param_9 + 0x30) + 0xf4);
      iVar1 = FUN_800396d0(param_9,0);
      if (((iVar1 == 0) || (8 < iVar3)) || (*(short *)(param_9 + 0xa0) == 5)) {
        if (((iVar1 != 0) && (8 < iVar3)) && (*(short *)(param_9 + 0xa0) != 9)) {
          *(undefined2 *)(iVar1 + 4) = 0;
          FUN_8003042c((double)FLOAT_803e65b4,param_2,param_3,param_4,param_5,param_6,param_7,
                       param_8,param_9,9,0,param_12,param_13,param_14,param_15,param_16);
        }
      }
      else {
        *(undefined2 *)(iVar1 + 4) = *(undefined2 *)(*(int *)(param_9 + 0x30) + 4);
        FUN_8003042c((double)FLOAT_803e65b4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,5,0,param_12,param_13,param_14,param_15,param_16);
      }
    }
    iVar1 = FUN_8002fb40((double)FLOAT_803e65b0,(double)FLOAT_803dc074);
    if (iVar1 != 0) {
      FUN_8000bb38(param_9,0x315);
    }
  }
  else {
    FUN_80014b68(0,0x100);
    (**(code **)(*DAT_803dd6d4 + 0x84))(param_9,0);
    (**(code **)(*DAT_803dd6d4 + 0x48))(3,param_9,0xffffffff);
    FUN_800201ac(0x92a,1);
  }
  return;
}

