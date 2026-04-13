// Function: FUN_80163e3c
// Entry: 80163e3c
// Size: 556 bytes

void FUN_80163e3c(short *param_1,int param_2)

{
  double dVar1;
  int iVar2;
  float local_58 [20];
  
  *(float *)(param_1 + 0x12) = *(float *)(param_1 + 0x12) / FLOAT_803e3bf4;
  iVar2 = FUN_80065800((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                       (double)*(float *)(param_1 + 10),param_1,local_58,0);
  if (iVar2 != 0) {
    if (local_58[0] <= FLOAT_803e3bf8) {
      *(float *)(param_1 + 8) = *(float *)(param_1 + 8) - (local_58[0] - FLOAT_803e3bf8);
      *(float *)(param_1 + 0x14) = FLOAT_803e3c00;
    }
    else {
      *(float *)(param_1 + 0x14) = FLOAT_803e3bfc * FLOAT_803dc074 + *(float *)(param_1 + 0x14);
    }
  }
  *(float *)(param_1 + 0x16) = *(float *)(param_1 + 0x16) / FLOAT_803e3bf4;
  iVar2 = (int)*(short *)(param_2 + 0x27c) / 100 + ((int)*(short *)(param_2 + 0x27c) >> 0x1f);
  *(short *)(param_2 + 0x27c) = (short)iVar2 - (short)(iVar2 >> 0x1f);
  iVar2 = (int)*(short *)(param_2 + 0x27e) / 100 + ((int)*(short *)(param_2 + 0x27e) >> 0x1f);
  *(short *)(param_2 + 0x27e) = (short)iVar2 - (short)(iVar2 >> 0x1f);
  iVar2 = (int)*(short *)(param_2 + 0x280) / 100 + ((int)*(short *)(param_2 + 0x280) >> 0x1f);
  *(short *)(param_2 + 0x280) = (short)iVar2 - (short)(iVar2 >> 0x1f);
  *(float *)(param_1 + 6) = *(float *)(param_1 + 0x12) * FLOAT_803dc074 + *(float *)(param_1 + 6);
  *(float *)(param_1 + 8) = *(float *)(param_1 + 0x14) * FLOAT_803dc074 + *(float *)(param_1 + 8);
  *(float *)(param_1 + 10) = *(float *)(param_1 + 0x16) * FLOAT_803dc074 + *(float *)(param_1 + 10);
  dVar1 = DOUBLE_803e3c08;
  param_1[2] = (short)(int)((float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)(param_2 + 0x27c) ^ 0x80000000)
                                   - DOUBLE_803e3c08) * FLOAT_803dc074 +
                           (float)((double)CONCAT44(0x43300000,(int)param_1[2] ^ 0x80000000) -
                                  DOUBLE_803e3c08));
  param_1[1] = (short)(int)((float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)(param_2 + 0x27e) ^ 0x80000000)
                                   - dVar1) * FLOAT_803dc074 +
                           (float)((double)CONCAT44(0x43300000,(int)param_1[1] ^ 0x80000000) - dVar1
                                  ));
  *param_1 = (short)(int)((float)((double)CONCAT44(0x43300000,
                                                   (int)*(short *)(param_2 + 0x280) ^ 0x80000000) -
                                 dVar1) * FLOAT_803dc074 +
                         (float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) - dVar1));
  return;
}

