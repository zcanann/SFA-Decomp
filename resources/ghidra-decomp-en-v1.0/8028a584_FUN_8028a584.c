// Function: FUN_8028a584
// Entry: 8028a584
// Size: 184 bytes

void FUN_8028a584(int param_1,undefined param_2,undefined param_3)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  FUN_802876f8(param_1,1);
  uVar1 = *(uint *)(param_1 + 0xc);
  if (uVar1 < 0x880) {
    *(uint *)(param_1 + 0xc) = uVar1 + 1;
    *(undefined *)(param_1 + uVar1 + 0x10) = param_2;
    *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
  }
  uVar1 = *(uint *)(param_1 + 0xc);
  if (uVar1 < 0x880) {
    *(uint *)(param_1 + 0xc) = uVar1 + 1;
    *(undefined *)(param_1 + uVar1 + 0x10) = param_3;
    *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
  }
  iVar3 = 3;
  do {
    iVar2 = FUN_80286cfc(param_1);
    iVar3 = iVar3 + -1;
    if (iVar2 == 0) {
      return;
    }
  } while (0 < iVar3);
  return;
}

