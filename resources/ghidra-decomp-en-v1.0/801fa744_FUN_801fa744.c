// Function: FUN_801fa744
// Entry: 801fa744
// Size: 240 bytes

void FUN_801fa744(int param_1)

{
  float fVar1;
  int iVar2;
  short *psVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  psVar3 = *(short **)(param_1 + 0xb8);
  if ((*(short *)(param_1 + 0x46) < 0x3ad) && (*(short *)(param_1 + 0x46) == 0x3a6)) {
    iVar2 = FUN_8001ffb4((int)*psVar3);
    fVar1 = FLOAT_803e60a8;
    if ((iVar2 == 0) || (*(float *)(param_1 + 0xc) <= *(float *)(iVar4 + 8) - FLOAT_803e60a8)) {
      iVar2 = FUN_8001ffb4((int)*psVar3);
      if ((iVar2 == 0) && (*(float *)(param_1 + 0xc) < *(float *)(iVar4 + 8))) {
        *(float *)(param_1 + 0xc) = *(float *)(param_1 + 0xc) + FLOAT_803e60b0;
        if (*(float *)(iVar4 + 8) < *(float *)(param_1 + 0xc)) {
          *(float *)(param_1 + 0xc) = *(float *)(iVar4 + 8);
        }
      }
    }
    else {
      *(float *)(param_1 + 0xc) = *(float *)(param_1 + 0xc) - FLOAT_803e60ac;
      fVar1 = *(float *)(iVar4 + 8) - fVar1;
      if (*(float *)(param_1 + 0xc) < fVar1) {
        *(float *)(param_1 + 0xc) = fVar1;
      }
    }
  }
  return;
}

