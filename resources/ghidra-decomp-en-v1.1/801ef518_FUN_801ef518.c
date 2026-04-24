// Function: FUN_801ef518
// Entry: 801ef518
// Size: 320 bytes

void FUN_801ef518(int param_1)

{
  char in_r8;
  float *pfVar1;
  float afStack_48 [16];
  
  pfVar1 = *(float **)(param_1 + 0xb8);
  if (in_r8 == -1) {
    FUN_8003b9ec(param_1);
    FUN_80038524(param_1,3,pfVar1,pfVar1 + 1,pfVar1 + 2,0);
    if (*(int *)(param_1 + 0x30) != 0) {
      *pfVar1 = *pfVar1 - FLOAT_803dda58;
      pfVar1[2] = pfVar1[2] - FLOAT_803dda5c;
      FUN_8002b454(*(short **)(param_1 + 0x30),afStack_48);
      FUN_80247bf8(afStack_48,pfVar1,pfVar1);
    }
  }
  else if (in_r8 == '\0') {
    *pfVar1 = *(float *)(param_1 + 0xc);
    pfVar1[1] = *(float *)(param_1 + 0x10);
    pfVar1[2] = *(float *)(param_1 + 0x14);
  }
  else {
    FUN_8003b9ec(param_1);
    FUN_80038524(param_1,3,pfVar1,pfVar1 + 1,pfVar1 + 2,0);
    if (*(int *)(param_1 + 0x30) != 0) {
      *pfVar1 = *pfVar1 - FLOAT_803dda58;
      pfVar1[2] = pfVar1[2] - FLOAT_803dda5c;
      FUN_8002b454(*(short **)(param_1 + 0x30),afStack_48);
      FUN_80247bf8(afStack_48,pfVar1,pfVar1);
    }
  }
  return;
}

