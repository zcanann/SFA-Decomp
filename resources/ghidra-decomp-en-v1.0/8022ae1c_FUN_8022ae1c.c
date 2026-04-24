// Function: FUN_8022ae1c
// Entry: 8022ae1c
// Size: 176 bytes

void FUN_8022ae1c(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  
  fVar1 = *(float *)(param_2 + 0x14) + *(float *)(param_2 + 0x20);
  fVar2 = *(float *)(param_2 + 0x14) - *(float *)(param_2 + 0x20);
  fVar3 = *(float *)(param_2 + 0x18) + *(float *)(param_2 + 0x28);
  fVar4 = *(float *)(param_2 + 0x18) - *(float *)(param_2 + 0x24);
  if (*(float *)(param_1 + 0xc) <= fVar1) {
    if (*(float *)(param_1 + 0xc) < fVar2) {
      *(float *)(param_1 + 0xc) = fVar2;
      *(float *)(param_2 + 0x48) = FLOAT_803e6ecc;
    }
  }
  else {
    *(float *)(param_1 + 0xc) = fVar1;
    *(float *)(param_2 + 0x48) = FLOAT_803e6ecc;
  }
  if (*(float *)(param_1 + 0x10) <= fVar3) {
    if (*(float *)(param_1 + 0x10) < fVar4) {
      *(float *)(param_1 + 0x10) = fVar4;
      *(float *)(param_2 + 0x4c) = FLOAT_803e6ecc;
    }
  }
  else {
    *(float *)(param_1 + 0x10) = fVar3;
    *(float *)(param_2 + 0x4c) = FLOAT_803e6ecc;
  }
  *(float *)(param_2 + 0x2c) = *(float *)(param_1 + 0xc) - *(float *)(param_2 + 0x14);
  *(float *)(param_2 + 0x30) = *(float *)(param_1 + 0x10) - *(float *)(param_2 + 0x18);
  *(float *)(param_2 + 0x34) = FLOAT_803e6ecc;
  return;
}

