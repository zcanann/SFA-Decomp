// Function: FUN_802271d4
// Entry: 802271d4
// Size: 216 bytes

void FUN_802271d4(undefined4 param_1,short param_2,short param_3,float *param_4,float *param_5)

{
  float fVar1;
  double dVar2;
  float local_28;
  float local_24 [5];
  
  FUN_8005b224(local_24,&local_28);
  dVar2 = DOUBLE_803e7a60;
  fVar1 = FLOAT_803e7a4c;
  *param_4 = FLOAT_803e7a4c +
             FLOAT_803e7a68 + local_24[0] +
             (float)((double)CONCAT44(0x43300000,param_2 * 0x30 ^ 0x80000000) - DOUBLE_803e7a60);
  *param_5 = fVar1 + FLOAT_803e7a6c + local_28 +
                     (float)((double)CONCAT44(0x43300000,param_3 * 0x30 ^ 0x80000000) - dVar2);
  return;
}

