// Function: FUN_80021ee8
// Entry: 80021ee8
// Size: 420 bytes

void FUN_80021ee8(float *param_1,undefined2 *param_2)

{
  float fVar1;
  float fVar2;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14 [3];
  
  FUN_80292f14(*param_2,local_14,&local_18);
  FUN_80292f14(param_2[1],&local_1c,&local_20);
  FUN_80292f14(param_2[2],&local_24,&local_28);
  fVar1 = *(float *)(param_2 + 4);
  *param_1 = fVar1 * (local_24 * local_1c * local_14[0] + local_28 * local_18);
  param_1[1] = fVar1 * local_24 * local_20;
  param_1[2] = fVar1 * (local_24 * local_1c * local_18 - local_28 * local_14[0]);
  fVar2 = FLOAT_803de7c0;
  param_1[3] = FLOAT_803de7c0;
  param_1[4] = fVar1 * (local_28 * local_1c * local_14[0] - local_24 * local_18);
  param_1[5] = fVar1 * local_28 * local_20;
  param_1[6] = fVar1 * (local_28 * local_1c * local_18 + local_24 * local_14[0]);
  param_1[7] = fVar2;
  param_1[8] = fVar1 * local_20 * local_14[0];
  param_1[9] = -local_1c * fVar1;
  param_1[10] = fVar1 * local_20 * local_18;
  param_1[0xb] = fVar2;
  param_1[0xc] = *(float *)(param_2 + 6);
  param_1[0xd] = *(float *)(param_2 + 8);
  param_1[0xe] = *(float *)(param_2 + 10);
  param_1[0xf] = FLOAT_803de7c4;
  return;
}

