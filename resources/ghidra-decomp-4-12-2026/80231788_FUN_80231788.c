// Function: FUN_80231788
// Entry: 80231788
// Size: 436 bytes

void FUN_80231788(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)

{
  float fVar1;
  float *pfVar2;
  double dVar3;
  double dVar4;
  
  fVar1 = FLOAT_803e7db4;
  pfVar2 = *(float **)(param_9 + 0x5c);
  dVar4 = (double)*pfVar2;
  dVar3 = (double)FLOAT_803e7db4;
  if ((dVar3 < dVar4) &&
     (*pfVar2 = (float)(dVar4 - (double)FLOAT_803dc074), (double)*pfVar2 <= dVar3)) {
    *pfVar2 = fVar1;
    FUN_8002cc9c(dVar3,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
    return;
  }
  fVar1 = FLOAT_803e7db8 * FLOAT_803dc074 +
          (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_9 + 0x1b)) - DOUBLE_803e7dc0);
  if (FLOAT_803e7dbc < fVar1) {
    fVar1 = FLOAT_803e7dbc;
  }
  *(char *)(param_9 + 0x1b) = (char)(int)fVar1;
  dVar3 = DOUBLE_803e7da8;
  *param_9 = (short)(int)((float)((double)CONCAT44(0x43300000,
                                                   (int)*(short *)(pfVar2 + 1) ^ 0x80000000) -
                                 DOUBLE_803e7da8) * FLOAT_803dc074 +
                         (float)((double)CONCAT44(0x43300000,(int)*param_9 ^ 0x80000000) -
                                DOUBLE_803e7da8));
  param_9[1] = (short)(int)((float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)((int)pfVar2 + 6) ^ 0x80000000)
                                   - dVar3) * FLOAT_803dc074 +
                           (float)((double)CONCAT44(0x43300000,(int)param_9[1] ^ 0x80000000) - dVar3
                                  ));
  param_9[2] = (short)(int)((float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)(pfVar2 + 2) ^ 0x80000000) -
                                   dVar3) * FLOAT_803dc074 +
                           (float)((double)CONCAT44(0x43300000,(int)param_9[2] ^ 0x80000000) - dVar3
                                  ));
  FUN_8002ba34((double)(*(float *)(param_9 + 0x12) * FLOAT_803dc074),
               (double)(*(float *)(param_9 + 0x14) * FLOAT_803dc074),
               (double)(*(float *)(param_9 + 0x16) * FLOAT_803dc074),(int)param_9);
  if (DAT_803dea14 == 0) {
    DAT_803dea14 = 1;
  }
  return;
}

