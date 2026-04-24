// Function: FUN_802313d4
// Entry: 802313d4
// Size: 344 bytes

void FUN_802313d4(short *param_1)

{
  double dVar1;
  float fVar2;
  float *pfVar3;
  
  fVar2 = FLOAT_803e713c;
  pfVar3 = *(float **)(param_1 + 0x5c);
  if ((*pfVar3 <= FLOAT_803e713c) || (*pfVar3 = *pfVar3 - FLOAT_803db414, fVar2 < *pfVar3)) {
    dVar1 = DOUBLE_803e7130;
    *param_1 = (short)(int)((float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)(pfVar3 + 1) ^ 0x80000000) -
                                   DOUBLE_803e7130) * FLOAT_803db414 +
                           (float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) -
                                  DOUBLE_803e7130));
    param_1[1] = (short)(int)((float)((double)CONCAT44(0x43300000,
                                                       (int)*(short *)((int)pfVar3 + 6) ^ 0x80000000
                                                      ) - dVar1) * FLOAT_803db414 +
                             (float)((double)CONCAT44(0x43300000,(int)param_1[1] ^ 0x80000000) -
                                    dVar1));
    param_1[2] = (short)(int)((float)((double)CONCAT44(0x43300000,
                                                       (int)*(short *)(pfVar3 + 2) ^ 0x80000000) -
                                     dVar1) * FLOAT_803db414 +
                             (float)((double)CONCAT44(0x43300000,(int)param_1[2] ^ 0x80000000) -
                                    dVar1));
    FUN_8002b95c((double)(*(float *)(param_1 + 0x12) * FLOAT_803db414),
                 (double)(*(float *)(param_1 + 0x14) * FLOAT_803db414),
                 (double)(*(float *)(param_1 + 0x16) * FLOAT_803db414));
  }
  else {
    *pfVar3 = fVar2;
    FUN_8002cbc4();
  }
  return;
}

