// Function: FUN_8021ba00
// Entry: 8021ba00
// Size: 44 bytes

void FUN_8021ba00(int param_1)

{
  float *pfVar1;
  
  pfVar1 = *(float **)(param_1 + 0xb8);
  if ((*(byte *)((int)pfVar1 + 0x179) >> 1 & 1) == 0) {
    return;
  }
  *(byte *)((int)pfVar1 + 0x179) = *(byte *)((int)pfVar1 + 0x179) & 0xfd;
  *pfVar1 = FLOAT_803e76d0;
  return;
}

