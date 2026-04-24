// Function: FUN_8028ac38
// Entry: 8028ac38
// Size: 176 bytes

void FUN_8028ac38(int param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  FUN_80287e5c(param_1,'\x01');
  uVar1 = *(uint *)(param_1 + 0xc);
  if (uVar1 < 0x880) {
    *(uint *)(param_1 + 0xc) = uVar1 + 1;
    *(undefined *)(param_1 + uVar1 + 0x10) = 0x80;
    *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
  }
  uVar1 = *(uint *)(param_1 + 0xc);
  if (uVar1 < 0x880) {
    *(uint *)(param_1 + 0xc) = uVar1 + 1;
    *(undefined *)(param_1 + uVar1 + 0x10) = 0x10;
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

