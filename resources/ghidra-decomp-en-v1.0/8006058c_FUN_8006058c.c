// Function: FUN_8006058c
// Entry: 8006058c
// Size: 100 bytes

void FUN_8006058c(undefined2 *param_1,float *param_2)

{
  float fVar1;
  float fVar2;
  
  fVar1 = FLOAT_803dec50 * param_2[1];
  fVar2 = FLOAT_803dec50 * param_2[2];
  *param_1 = (short)(int)(FLOAT_803dec50 * *param_2);
  param_1[1] = (short)(int)fVar1;
  param_1[2] = (short)(int)fVar2;
  return;
}

