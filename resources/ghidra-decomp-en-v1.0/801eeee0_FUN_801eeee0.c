// Function: FUN_801eeee0
// Entry: 801eeee0
// Size: 320 bytes

void FUN_801eeee0(int param_1)

{
  char in_r8;
  float *pfVar1;
  undefined auStack72 [64];
  
  pfVar1 = *(float **)(param_1 + 0xb8);
  if (in_r8 == -1) {
    FUN_8003b8f4((double)FLOAT_803e5c74);
    FUN_8003842c(param_1,3,pfVar1,pfVar1 + 1,pfVar1 + 2,0);
    if (*(int *)(param_1 + 0x30) != 0) {
      *pfVar1 = *pfVar1 - FLOAT_803dcdd8;
      pfVar1[2] = pfVar1[2] - FLOAT_803dcddc;
      FUN_8002b37c(*(undefined4 *)(param_1 + 0x30),auStack72);
      FUN_80247494(auStack72,pfVar1,pfVar1);
    }
  }
  else if (in_r8 == '\0') {
    *pfVar1 = *(float *)(param_1 + 0xc);
    pfVar1[1] = *(float *)(param_1 + 0x10);
    pfVar1[2] = *(float *)(param_1 + 0x14);
  }
  else {
    FUN_8003b8f4((double)FLOAT_803e5c74);
    FUN_8003842c(param_1,3,pfVar1,pfVar1 + 1,pfVar1 + 2,0);
    if (*(int *)(param_1 + 0x30) != 0) {
      *pfVar1 = *pfVar1 - FLOAT_803dcdd8;
      pfVar1[2] = pfVar1[2] - FLOAT_803dcddc;
      FUN_8002b37c(*(undefined4 *)(param_1 + 0x30),auStack72);
      FUN_80247494(auStack72,pfVar1,pfVar1);
    }
  }
  return;
}

