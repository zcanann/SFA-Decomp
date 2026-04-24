// Function: FUN_800701a4
// Entry: 800701a4
// Size: 144 bytes

void FUN_800701a4(float *param_1,float *param_2,float *param_3)

{
  float fVar1;
  double dVar2;
  
  dVar2 = (double)FUN_802931a0((double)(*param_3 * *param_3 +
                                       *param_1 * *param_1 + *param_2 * *param_2));
  fVar1 = (float)((double)FLOAT_803dee90 / dVar2);
  *param_1 = *param_1 * fVar1;
  *param_2 = *param_2 * fVar1;
  *param_3 = *param_3 * fVar1;
  return;
}

