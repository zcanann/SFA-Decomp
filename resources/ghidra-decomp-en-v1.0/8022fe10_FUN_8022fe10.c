// Function: FUN_8022fe10
// Entry: 8022fe10
// Size: 64 bytes

void FUN_8022fe10(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(int *)(iVar1 + 0x20) != 0) {
    FUN_8001f384();
    *(undefined4 *)(iVar1 + 0x20) = 0;
  }
  return;
}

