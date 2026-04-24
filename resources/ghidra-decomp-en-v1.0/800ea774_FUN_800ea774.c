// Function: FUN_800ea774
// Entry: 800ea774
// Size: 108 bytes

void FUN_800ea774(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(undefined *)(iVar1 + 5) = 0;
  *(undefined *)(iVar1 + 6) = 0;
  if ((*(byte *)(iVar1 + 7) & 8) == 0) {
    *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) + FLOAT_803e06d8;
    FUN_800e8370();
    *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) - FLOAT_803e06d8;
  }
  return;
}

