// Function: FUN_8018d378
// Entry: 8018d378
// Size: 224 bytes

void FUN_8018d378(undefined2 *param_1,int param_2)

{
  float fVar1;
  uint uVar2;
  
  param_1[3] = param_1[3] | 2;
  uVar2 = *(byte *)(param_2 + 0x19) ^ 0x80000000;
  fVar1 = (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e4a08);
  if ((float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e4a08) < FLOAT_803e49fc) {
    fVar1 = FLOAT_803e49fc;
  }
  fVar1 = fVar1 * FLOAT_803e4a00;
  *(float *)(param_1 + 4) = *(float *)(*(int *)(param_1 + 0x28) + 4) * fVar1;
  if (*(float **)(param_1 + 0x32) != (float *)0x0) {
    **(float **)(param_1 + 0x32) = **(float **)(param_1 + 0x28) * fVar1;
  }
  *(undefined *)((int)param_1 + 0xad) = *(undefined *)(param_2 + 0x18);
  *param_1 = (short)((*(byte *)(param_2 + 0x1a) & 0x3f) << 10);
  if (*(char *)(*(int *)(param_1 + 0x28) + 0x55) <= *(char *)((int)param_1 + 0xad)) {
    *(undefined *)((int)param_1 + 0xad) = 0;
  }
  *(undefined4 *)(param_1 + 0x7a) = 0;
  *(undefined4 *)(param_1 + 0x7c) = 0;
  return;
}

