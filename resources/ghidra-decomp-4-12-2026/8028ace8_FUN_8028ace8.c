// Function: FUN_8028ace8
// Entry: 8028ace8
// Size: 184 bytes

void FUN_8028ace8(int param_1,undefined param_2,undefined param_3)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  FUN_80287e5c(param_1,'\x01');
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
    iVar2 = FUN_80287460(param_1);
    iVar3 = iVar3 + -1;
    if (iVar2 == 0) {
      return;
    }
  } while (0 < iVar3);
  return;
}

