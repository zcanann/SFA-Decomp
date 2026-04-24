// Function: FUN_8014c63c
// Entry: 8014c63c
// Size: 48 bytes

void FUN_8014c63c(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  uVar1 = FUN_8002b9ec();
  *(undefined4 *)(iVar2 + 0x29c) = uVar1;
  return;
}

