// Function: FUN_802310c4
// Entry: 802310c4
// Size: 436 bytes

void FUN_802310c4(short *param_1)

{
  float fVar1;
  double dVar2;
  float *pfVar3;
  
  fVar1 = FLOAT_803e711c;
  pfVar3 = *(float **)(param_1 + 0x5c);
  if ((*pfVar3 <= FLOAT_803e711c) || (*pfVar3 = *pfVar3 - FLOAT_803db414, fVar1 < *pfVar3)) {
    fVar1 = FLOAT_803e7120 * FLOAT_803db414 +
            (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x1b)) - DOUBLE_803e7128);
    if (FLOAT_803e7124 < fVar1) {
      fVar1 = FLOAT_803e7124;
    }
    *(char *)(param_1 + 0x1b) = (char)(int)fVar1;
    dVar2 = DOUBLE_803e7110;
    *param_1 = (short)(int)((float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)(pfVar3 + 1) ^ 0x80000000) -
                                   DOUBLE_803e7110) * FLOAT_803db414 +
                           (float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) -
                                  DOUBLE_803e7110));
    param_1[1] = (short)(int)((float)((double)CONCAT44(0x43300000,
                                                       (int)*(short *)((int)pfVar3 + 6) ^ 0x80000000
                                                      ) - dVar2) * FLOAT_803db414 +
                             (float)((double)CONCAT44(0x43300000,(int)param_1[1] ^ 0x80000000) -
                                    dVar2));
    param_1[2] = (short)(int)((float)((double)CONCAT44(0x43300000,
                                                       (int)*(short *)(pfVar3 + 2) ^ 0x80000000) -
                                     dVar2) * FLOAT_803db414 +
                             (float)((double)CONCAT44(0x43300000,(int)param_1[2] ^ 0x80000000) -
                                    dVar2));
    FUN_8002b95c((double)(*(float *)(param_1 + 0x12) * FLOAT_803db414),
                 (double)(*(float *)(param_1 + 0x14) * FLOAT_803db414),
                 (double)(*(float *)(param_1 + 0x16) * FLOAT_803db414));
    if (DAT_803ddd94 == 0) {
      DAT_803ddd94 = 1;
    }
  }
  else {
    *pfVar3 = fVar1;
    FUN_8002cbc4();
  }
  return;
}

