// Function: FUN_8014cab4
// Entry: 8014cab4
// Size: 48 bytes

void FUN_8014cab4(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  uVar1 = FUN_8002bac4();
  *(undefined4 *)(iVar2 + 0x29c) = uVar1;
  return;
}

