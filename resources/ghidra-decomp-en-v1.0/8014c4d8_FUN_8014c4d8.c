// Function: FUN_8014c4d8
// Entry: 8014c4d8
// Size: 104 bytes

uint FUN_8014c4d8(int param_1)

{
  float fVar1;
  uint uVar2;
  
  if (param_1 == 0) {
    uVar2 = 0;
  }
  else if (*(int *)(param_1 + 0xb8) == 0) {
    uVar2 = 0;
  }
  else {
    fVar1 = *(float *)(*(int *)(param_1 + 0xb8) + 0x2d8);
    if (fVar1 == FLOAT_803e2574) {
      uVar2 = 0;
    }
    else {
      uVar2 = (int)(fVar1 / FLOAT_803e2598) + 1U & 0xff;
    }
  }
  return uVar2;
}

