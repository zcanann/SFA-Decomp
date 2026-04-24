// Function: FUN_8016bc8c
// Entry: 8016bc8c
// Size: 176 bytes

void FUN_8016bc8c(undefined2 *param_1)

{
  float *pfVar1;
  float local_18 [4];
  
  pfVar1 = *(float **)(param_1 + 0x5c);
  FUN_80065800((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
               (double)*(float *)(param_1 + 10),param_1,local_18,0);
  FUN_80035ff8((int)param_1);
  *(undefined *)(param_1 + 0x1b) = 0xff;
  param_1[1] = 0x4000;
  *param_1 = 0;
  param_1[2] = 0;
  *(uint *)(*(int *)(param_1 + 0x32) + 0x30) = *(uint *)(*(int *)(param_1 + 0x32) + 0x30) | 0x10000;
  *pfVar1 = local_18[0];
  *(float *)(param_1 + 8) = *(float *)(param_1 + 8) - local_18[0];
  *(undefined2 *)(*(int *)(param_1 + 0x32) + 0x36) = 0;
  **(float **)(param_1 + 0x32) = FLOAT_803e3e70;
  return;
}

