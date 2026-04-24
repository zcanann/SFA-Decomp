// Function: FUN_80021ac8
// Entry: 80021ac8
// Size: 216 bytes

void FUN_80021ac8(undefined2 *param_1,float *param_2)

{
  float fVar1;
  float fVar2;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14 [3];
  
  FUN_80292f14(*param_1,&local_24,&local_28);
  FUN_80292f14(param_1[1],&local_1c,&local_20);
  FUN_80292f14(param_1[2],local_14,&local_18);
  fVar2 = *param_2 * local_18 - param_2[1] * local_14[0];
  fVar1 = param_2[1] * local_18 + *param_2 * local_14[0];
  param_2[1] = fVar1 * local_20 - param_2[2] * local_1c;
  fVar1 = param_2[2] * local_20 + fVar1 * local_1c;
  *param_2 = fVar2 * local_28 + fVar1 * local_24;
  param_2[2] = fVar1 * local_28 - fVar2 * local_24;
  return;
}

