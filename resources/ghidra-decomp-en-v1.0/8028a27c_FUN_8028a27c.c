// Function: FUN_8028a27c
// Entry: 8028a27c
// Size: 184 bytes

undefined4 FUN_8028a27c(int param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  FUN_802876f8(param_1,1);
  uVar1 = *(uint *)(param_1 + 0xc);
  if (uVar1 < 0x880) {
    *(uint *)(param_1 + 0xc) = uVar1 + 1;
    *(undefined *)(param_1 + uVar1 + 0x10) = 0x80;
    *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
  }
  uVar1 = *(uint *)(param_1 + 0xc);
  if (uVar1 < 0x880) {
    *(uint *)(param_1 + 0xc) = uVar1 + 1;
    *(undefined *)(param_1 + uVar1 + 0x10) = 0;
    *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
  }
  iVar3 = 3;
  do {
    iVar2 = FUN_80286cfc(param_1);
    iVar3 = iVar3 + -1;
    if (iVar2 == 0) break;
  } while (0 < iVar3);
  FUN_8000546c();
  return 0;
}

