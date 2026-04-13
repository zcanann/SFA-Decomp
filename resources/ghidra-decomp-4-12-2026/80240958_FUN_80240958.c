// Function: FUN_80240958
// Entry: 80240958
// Size: 48 bytes

void FUN_80240958(int param_1)

{
  float *pfVar1;
  
  pfVar1 = *(float **)(*(int *)(param_1 + 0xb8) + 4);
  if (pfVar1 != (float *)0x0) {
    FUN_8008fb90(pfVar1);
  }
  return;
}

