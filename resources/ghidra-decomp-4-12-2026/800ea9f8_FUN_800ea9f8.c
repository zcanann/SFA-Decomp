// Function: FUN_800ea9f8
// Entry: 800ea9f8
// Size: 120 bytes

void FUN_800ea9f8(int param_1)

{
  int iVar1;
  
  if (*(short *)(param_1 + 0x46) != 0x112) {
    iVar1 = *(int *)(param_1 + 0xb8);
    *(undefined *)(iVar1 + 5) = 0;
    *(undefined *)(iVar1 + 6) = 0;
    if ((*(byte *)(iVar1 + 7) & 8) == 0) {
      *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) + FLOAT_803e1358;
      FUN_800e85f4(param_1);
      *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) - FLOAT_803e1358;
    }
  }
  return;
}

