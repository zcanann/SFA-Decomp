// Function: FUN_80070320
// Entry: 80070320
// Size: 144 bytes

void FUN_80070320(float *param_1,float *param_2,float *param_3)

{
  float fVar1;
  double dVar2;
  
  dVar2 = FUN_80293900((double)(*param_3 * *param_3 + *param_1 * *param_1 + *param_2 * *param_2));
  fVar1 = (float)((double)FLOAT_803dfb10 / dVar2);
  *param_1 = *param_1 * fVar1;
  *param_2 = *param_2 * fVar1;
  *param_3 = *param_3 * fVar1;
  return;
}

