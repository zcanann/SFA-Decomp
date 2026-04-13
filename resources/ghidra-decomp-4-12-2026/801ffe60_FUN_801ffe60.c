// Function: FUN_801ffe60
// Entry: 801ffe60
// Size: 84 bytes

void FUN_801ffe60(short *param_1)

{
  int iVar1;
  
  FUN_801fe954(param_1,*(undefined4 **)(param_1 + 0x5c));
  FUN_80037a5c((int)param_1,8);
  iVar1 = *(int *)(param_1 + 0x32);
  if (iVar1 != 0) {
    *(uint *)(iVar1 + 0x30) = *(uint *)(iVar1 + 0x30) | 0x4008;
  }
  return;
}

