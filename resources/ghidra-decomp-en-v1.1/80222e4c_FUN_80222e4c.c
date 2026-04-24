// Function: FUN_80222e4c
// Entry: 80222e4c
// Size: 72 bytes

void FUN_80222e4c(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(int *)(iVar1 + 8) != 0) {
    FUN_801a110c(*(int *)(iVar1 + 8));
    *(byte *)(iVar1 + 0x12a) = *(byte *)(iVar1 + 0x12a) & 0x7f;
  }
  return;
}

