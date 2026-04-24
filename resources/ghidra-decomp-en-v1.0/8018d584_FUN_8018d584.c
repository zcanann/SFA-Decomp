// Function: FUN_8018d584
// Entry: 8018d584
// Size: 348 bytes

void FUN_8018d584(undefined2 *param_1,int param_2)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  
  param_1[3] = param_1[3] | 2;
  uVar2 = *(byte *)(param_2 + 0x1c) ^ 0x80000000;
  fVar1 = (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e3dd0);
  if ((float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e3dd0) < FLOAT_803e3dc0) {
    fVar1 = FLOAT_803e3dc0;
  }
  fVar1 = fVar1 * FLOAT_803e3dc4;
  *(float *)(param_1 + 4) = *(float *)(*(int *)(param_1 + 0x28) + 4) * fVar1;
  *param_1 = (short)((*(byte *)(param_2 + 0x1d) & 0x3f) << 10);
  if (*(float **)(param_1 + 0x32) != (float *)0x0) {
    **(float **)(param_1 + 0x32) = **(float **)(param_1 + 0x28) * fVar1;
  }
  *(undefined *)((int)param_1 + 0xad) = *(undefined *)(param_2 + 0x18);
  if (*(char *)(*(int *)(param_1 + 0x28) + 0x55) <= *(char *)((int)param_1 + 0xad)) {
    *(undefined *)((int)param_1 + 0xad) = 0;
  }
  FUN_80030334((double)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x1a)) -
                               DOUBLE_803e3db8) * FLOAT_803e3dc8),param_1,
               *(undefined *)(param_2 + 0x19),0);
  if (*(short *)(param_2 + 0x20) != -1) {
    iVar3 = FUN_8001ffb4();
    if (iVar3 == 0) {
      *(undefined *)(param_1 + 0x1b) = 0;
    }
    else {
      *(undefined *)(param_1 + 0x1b) = 0xff;
    }
  }
  return;
}

