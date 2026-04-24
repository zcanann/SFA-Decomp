// Function: FUN_80113b00
// Entry: 80113b00
// Size: 248 bytes

void FUN_80113b00(double param_1,double param_2,short *param_3,int param_4)

{
  float fVar1;
  
  if (*(float *)(param_4 + 0x298) < FLOAT_803e28f8) {
    *(undefined2 *)(param_4 + 0x334) = 0;
    *(undefined2 *)(param_4 + 0x336) = 0;
    fVar1 = FLOAT_803e28ac;
    *(float *)(param_4 + 0x298) = FLOAT_803e28ac;
    *(float *)(param_4 + 0x280) = fVar1;
  }
  *(float *)(param_4 + 0x284) = FLOAT_803e28ac;
  *param_3 = (short)(int)(FLOAT_803e28fc *
                          (float)((double)((float)((double)CONCAT44(0x43300000,
                                                                    (int)*(short *)(param_4 + 0x336)
                                                                    ^ 0x80000000) - DOUBLE_803e28b0)
                                          * FLOAT_803dc074) / param_2) +
                         (float)((double)CONCAT44(0x43300000,(int)*param_3 ^ 0x80000000) -
                                DOUBLE_803e28b0));
  *(float *)(param_4 + 0x294) =
       FLOAT_803dc074 *
       ((*(float *)(param_4 + 0x298) - *(float *)(param_4 + 0x294)) / *(float *)(param_4 + 0x2b8)) +
       *(float *)(param_4 + 0x294);
  *(float *)(param_4 + 0x280) =
       FLOAT_803dc074 *
       ((*(float *)(param_4 + 0x298) - *(float *)(param_4 + 0x280)) / *(float *)(param_4 + 0x2b8)) +
       *(float *)(param_4 + 0x280);
  if (param_1 < (double)*(float *)(param_4 + 0x294)) {
    *(float *)(param_4 + 0x294) = (float)param_1;
  }
  if (param_1 < (double)*(float *)(param_4 + 0x280)) {
    *(float *)(param_4 + 0x280) = (float)param_1;
  }
  return;
}

