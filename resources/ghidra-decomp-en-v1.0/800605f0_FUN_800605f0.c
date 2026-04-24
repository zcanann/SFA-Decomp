// Function: FUN_800605f0
// Entry: 800605f0
// Size: 120 bytes

void FUN_800605f0(short *param_1,float *param_2)

{
  double dVar1;
  float fVar2;
  
  fVar2 = FLOAT_803dec20;
  dVar1 = DOUBLE_803debc0;
  *param_2 = (float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) - DOUBLE_803debc0) *
             FLOAT_803dec20;
  param_2[1] = (float)((double)CONCAT44(0x43300000,(int)param_1[1] ^ 0x80000000) - dVar1) * fVar2;
  param_2[2] = (float)((double)CONCAT44(0x43300000,(int)param_1[2] ^ 0x80000000) - dVar1) * fVar2;
  return;
}

