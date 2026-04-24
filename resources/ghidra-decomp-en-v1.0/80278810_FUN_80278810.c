// Function: FUN_80278810
// Entry: 80278810
// Size: 164 bytes

void FUN_80278810(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = DAT_803de2d8;
  iVar2 = 0;
  while ((iVar3 = iVar1, iVar3 != 0 &&
         (*(uint *)(iVar3 + 0x98) <
          (uint)(*(uint *)(iVar3 + 0x9c) < *(uint *)(param_1 + 0x9c)) + *(int *)(param_1 + 0x98))))
  {
    iVar2 = iVar3;
    iVar1 = *(int *)(iVar3 + 0x44);
  }
  if (iVar3 != 0) {
    *(int *)(param_1 + 0x44) = iVar3;
    iVar2 = *(int *)(iVar3 + 0x48);
    *(int *)(param_1 + 0x48) = iVar2;
    iVar1 = param_1;
    if (iVar2 != 0) {
      *(int *)(*(int *)(iVar3 + 0x48) + 0x44) = param_1;
      iVar1 = DAT_803de2d8;
    }
    DAT_803de2d8 = iVar1;
    *(int *)(iVar3 + 0x48) = param_1;
    return;
  }
  if (iVar2 != 0) {
    *(int *)(iVar2 + 0x44) = param_1;
    *(int *)(param_1 + 0x48) = iVar2;
    *(undefined4 *)(param_1 + 0x44) = 0;
    return;
  }
  DAT_803de2d8 = param_1;
  *(undefined4 *)(param_1 + 0x44) = 0;
  *(undefined4 *)(param_1 + 0x48) = 0;
  return;
}

