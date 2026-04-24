// Function: FUN_801fb78c
// Entry: 801fb78c
// Size: 116 bytes

void FUN_801fb78c(int param_1)

{
  int iVar1;
  
  if ((*(short *)(*(int *)(param_1 + 0xb8) + 0xc) == -1) || (iVar1 = FUN_8001ffb4(), iVar1 != 0)) {
    if ((*(byte *)(param_1 + 0xaf) & 8) != 0) {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) ^ 8;
    }
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  }
  return;
}

