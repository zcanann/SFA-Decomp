// Function: FUN_80178fd4
// Entry: 80178fd4
// Size: 100 bytes

void FUN_80178fd4(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if ((*(short *)(iVar2 + 0x1c) != 0) && (iVar1 = FUN_8000b5d0(), iVar1 != 0)) {
    FUN_8000b824(param_1,*(undefined2 *)(iVar2 + 0x1c));
  }
  FUN_80036fa4(param_1,0xe);
  return;
}

