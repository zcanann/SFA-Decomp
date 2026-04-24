// Function: FUN_801fad7c
// Entry: 801fad7c
// Size: 240 bytes

void FUN_801fad7c(int param_1)

{
  float fVar1;
  uint uVar2;
  short *psVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  psVar3 = *(short **)(param_1 + 0xb8);
  if ((*(short *)(param_1 + 0x46) < 0x3ad) && (*(short *)(param_1 + 0x46) == 0x3a6)) {
    uVar2 = FUN_80020078((int)*psVar3);
    fVar1 = FLOAT_803e6d40;
    if ((uVar2 == 0) || (*(float *)(param_1 + 0xc) <= *(float *)(iVar4 + 8) - FLOAT_803e6d40)) {
      uVar2 = FUN_80020078((int)*psVar3);
      if ((uVar2 == 0) && (*(float *)(param_1 + 0xc) < *(float *)(iVar4 + 8))) {
        *(float *)(param_1 + 0xc) = *(float *)(param_1 + 0xc) + FLOAT_803e6d48;
        if (*(float *)(iVar4 + 8) < *(float *)(param_1 + 0xc)) {
          *(float *)(param_1 + 0xc) = *(float *)(iVar4 + 8);
        }
      }
    }
    else {
      *(float *)(param_1 + 0xc) = *(float *)(param_1 + 0xc) - FLOAT_803e6d44;
      fVar1 = *(float *)(iVar4 + 8) - fVar1;
      if (*(float *)(param_1 + 0xc) < fVar1) {
        *(float *)(param_1 + 0xc) = fVar1;
      }
    }
  }
  return;
}

