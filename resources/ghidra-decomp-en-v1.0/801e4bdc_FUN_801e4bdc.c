// Function: FUN_801e4bdc
// Entry: 801e4bdc
// Size: 644 bytes

void FUN_801e4bdc(int param_1)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  int local_18;
  int local_14 [2];
  
  piVar3 = *(int **)(param_1 + 0xb8);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  if (*piVar3 == 0) {
    iVar1 = FUN_8002e0fc(&local_18,local_14);
    for (local_18 = 0; local_18 < local_14[0]; local_18 = local_18 + 1) {
      iVar2 = *(int *)(iVar1 + local_18 * 4);
      if (*(short *)(iVar2 + 0x46) == 0x121) {
        *piVar3 = iVar2;
        FUN_80037d2c(param_1,*piVar3,1);
        local_18 = local_14[0];
      }
    }
  }
  if (((*(byte *)(param_1 + 0xaf) & 4) == 0) || (iVar1 = FUN_8001ffb4(0x92a), iVar1 != 0)) {
    if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
      FUN_80014b3c(0,0x100);
      (**(code **)(*DAT_803dca54 + 0x84))(param_1,0);
      if (*(char *)((int)piVar3 + 5) == '\0') {
        (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
        *(undefined *)((int)piVar3 + 5) = 1;
      }
      else {
        (**(code **)(*DAT_803dca54 + 0x48))(2,param_1,0xffffffff);
      }
    }
    if (*(int *)(param_1 + 0x30) != 0) {
      iVar2 = *(int *)(*(int *)(param_1 + 0x30) + 0xf4);
      iVar1 = FUN_800395d8(param_1,0);
      if (((iVar1 == 0) || (8 < iVar2)) || (*(short *)(param_1 + 0xa0) == 5)) {
        if (((iVar1 != 0) && (8 < iVar2)) && (*(short *)(param_1 + 0xa0) != 9)) {
          *(undefined2 *)(iVar1 + 4) = 0;
          FUN_80030334((double)FLOAT_803e591c,param_1,9,0);
        }
      }
      else {
        *(undefined2 *)(iVar1 + 4) = *(undefined2 *)(*(int *)(param_1 + 0x30) + 4);
        FUN_80030334((double)FLOAT_803e591c,param_1,5,0);
      }
    }
    iVar1 = FUN_8002fa48((double)FLOAT_803e5918,(double)FLOAT_803db414,param_1,0);
    if (iVar1 != 0) {
      FUN_8000bb18(param_1,0x315);
    }
  }
  else {
    FUN_80014b3c(0,0x100);
    (**(code **)(*DAT_803dca54 + 0x84))(param_1,0);
    (**(code **)(*DAT_803dca54 + 0x48))(3,param_1,0xffffffff);
    FUN_800200e8(0x92a,1);
  }
  return;
}

