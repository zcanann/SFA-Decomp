// Function: FUN_80060708
// Entry: 80060708
// Size: 100 bytes

void FUN_80060708(undefined2 *param_1,float *param_2)

{
  float fVar1;
  float fVar2;
  
  fVar1 = FLOAT_803df8d0 * param_2[1];
  fVar2 = FLOAT_803df8d0 * param_2[2];
  *param_1 = (short)(int)(FLOAT_803df8d0 * *param_2);
  param_1[1] = (short)(int)fVar1;
  param_1[2] = (short)(int)fVar2;
  return;
}

