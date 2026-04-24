// Function: FUN_80226b84
// Entry: 80226b84
// Size: 216 bytes

void FUN_80226b84(int param_1,short param_2,short param_3,float *param_4,float *param_5)

{
  float fVar1;
  double dVar2;
  float local_28;
  float local_24 [5];
  
  FUN_8005b0a8((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
               (double)*(float *)(param_1 + 0x14),local_24,&local_28);
  dVar2 = DOUBLE_803e6dc8;
  fVar1 = FLOAT_803e6db4;
  *param_4 = FLOAT_803e6db4 +
             FLOAT_803e6dd0 + local_24[0] +
             (float)((double)CONCAT44(0x43300000,param_2 * 0x30 ^ 0x80000000) - DOUBLE_803e6dc8);
  *param_5 = fVar1 + FLOAT_803e6dd4 + local_28 +
                     (float)((double)CONCAT44(0x43300000,param_3 * 0x30 ^ 0x80000000) - dVar2);
  return;
}

