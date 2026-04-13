// Function: FUN_80157d44
// Entry: 80157d44
// Size: 240 bytes

void FUN_80157d44(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  uint uVar4;
  
  uVar4 = (uint)*(byte *)(*(int *)(param_1 + 0x4c) + 0x2f);
  fVar1 = (float)((double)CONCAT44(0x43300000,uVar4) - DOUBLE_803e37f0);
  if (FLOAT_803e37b0 == (float)((double)CONCAT44(0x43300000,uVar4) - DOUBLE_803e37f0)) {
    fVar1 = FLOAT_803e37d0;
  }
  fVar1 = fVar1 / FLOAT_803e37d0;
  *(float *)(param_2 + 0x2ac) = FLOAT_803e37fc;
  *(undefined4 *)(param_2 + 0x2e4) = 0x8b;
  *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x20;
  *(float *)(param_2 + 0x308) = FLOAT_803e3800 * fVar1;
  fVar2 = FLOAT_803e37d8;
  *(float *)(param_2 + 0x300) = FLOAT_803e37d8;
  *(float *)(param_2 + 0x304) = FLOAT_803e3804;
  *(undefined *)(param_2 + 800) = 0;
  *(float *)(param_2 + 0x314) = FLOAT_803e3808;
  *(undefined *)(param_2 + 0x321) = 3;
  fVar3 = FLOAT_803e37e4;
  *(float *)(param_2 + 0x318) = FLOAT_803e37e4;
  *(undefined *)(param_2 + 0x322) = 5;
  *(float *)(param_2 + 0x31c) = fVar3;
  *(undefined2 *)(param_2 + 0x338) = 0;
  *(float *)(param_2 + 0x324) = FLOAT_803e380c;
  *(float *)(param_2 + 0x328) = fVar2;
  *(undefined *)(param_1 + 0x36) = 0;
  *(float *)(param_2 + 0x2fc) = FLOAT_803e3810 * fVar1;
  *(undefined4 *)(param_2 + 0x2e8) = 0;
  FUN_80036018(param_1);
  return;
}

