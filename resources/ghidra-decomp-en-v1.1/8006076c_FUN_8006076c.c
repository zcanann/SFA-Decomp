// Function: FUN_8006076c
// Entry: 8006076c
// Size: 120 bytes

void FUN_8006076c(short *param_1,float *param_2)

{
  double dVar1;
  float fVar2;
  
  fVar2 = FLOAT_803df8a0;
  dVar1 = DOUBLE_803df840;
  *param_2 = (float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) - DOUBLE_803df840) *
             FLOAT_803df8a0;
  param_2[1] = (float)((double)CONCAT44(0x43300000,(int)param_1[1] ^ 0x80000000) - dVar1) * fVar2;
  param_2[2] = (float)((double)CONCAT44(0x43300000,(int)param_1[2] ^ 0x80000000) - dVar1) * fVar2;
  return;
}

