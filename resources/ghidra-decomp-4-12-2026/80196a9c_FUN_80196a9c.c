// Function: FUN_80196a9c
// Entry: 80196a9c
// Size: 1008 bytes

/* WARNING: Removing unreachable block (ram,0x80196e68) */
/* WARNING: Removing unreachable block (ram,0x80196e60) */
/* WARNING: Removing unreachable block (ram,0x80196e58) */
/* WARNING: Removing unreachable block (ram,0x80196e50) */
/* WARNING: Removing unreachable block (ram,0x80196ac4) */
/* WARNING: Removing unreachable block (ram,0x80196abc) */
/* WARNING: Removing unreachable block (ram,0x80196ab4) */
/* WARNING: Removing unreachable block (ram,0x80196aac) */

void FUN_80196a9c(undefined2 *param_1,int param_2,int param_3)

{
  float fVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  
  *(float *)(param_1 + 6) =
       *(float *)(param_2 + 0x26c) * *(float *)(param_1 + 4) + *(float *)(param_3 + 8);
  *(float *)(param_1 + 8) =
       *(float *)(param_2 + 0x270) * *(float *)(param_1 + 4) + *(float *)(param_3 + 0xc);
  *(float *)(param_1 + 10) =
       *(float *)(param_2 + 0x274) * *(float *)(param_1 + 4) + *(float *)(param_3 + 0x10);
  *param_1 = *(undefined2 *)(param_3 + 0x1a);
  param_1[1] = *(undefined2 *)(param_3 + 0x1c);
  param_1[2] = *(undefined2 *)(param_3 + 0x1e);
  dVar2 = DOUBLE_803e4cd8;
  fVar1 = FLOAT_803e4cc8;
  if ((*(byte *)(param_3 + 0x3c) & 1) == 0) {
    *(float *)(param_1 + 0x12) =
         (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x20) ^ 0x80000000) -
                DOUBLE_803e4cd8) / FLOAT_803e4cc8;
    *(float *)(param_1 + 0x14) =
         (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x22) ^ 0x80000000) - dVar2)
         / fVar1;
    *(float *)(param_1 + 0x16) =
         (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x24) ^ 0x80000000) - dVar2)
         / fVar1;
  }
  else {
    dVar6 = (double)((float)((double)CONCAT44(0x43300000,
                                              (int)*(short *)(param_3 + 0x20) ^ 0x80000000) -
                            DOUBLE_803e4cd8) / FLOAT_803e4cc8);
    dVar5 = (double)(*(float *)(param_1 + 6) -
                    (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x42) ^ 0x80000000
                                            ) - DOUBLE_803e4cd8));
    dVar4 = (double)(*(float *)(param_1 + 8) -
                    (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x44) ^ 0x80000000
                                            ) - DOUBLE_803e4cd8));
    dVar3 = (double)(*(float *)(param_1 + 10) -
                    (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x46) ^ 0x80000000
                                            ) - DOUBLE_803e4cd8));
    dVar2 = FUN_80293900((double)(float)(dVar3 * dVar3 +
                                        (double)(float)(dVar5 * dVar5 +
                                                       (double)(float)(dVar4 * dVar4))));
    if ((double)FLOAT_803e4ccc != dVar2) {
      dVar5 = (double)(float)(dVar5 / dVar2);
      dVar4 = (double)(float)(dVar4 / dVar2);
      dVar3 = (double)(float)(dVar3 / dVar2);
    }
    *(float *)(param_1 + 0x12) = (float)(dVar6 * dVar5);
    *(float *)(param_1 + 0x14) = (float)(dVar6 * dVar4);
    *(float *)(param_1 + 0x16) = (float)(dVar6 * dVar3);
  }
  dVar2 = DOUBLE_803e4cd8;
  *(float *)(param_2 + 0x278) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x2c) ^ 0x80000000) -
              DOUBLE_803e4cd8);
  *(float *)(param_2 + 0x27c) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x2e) ^ 0x80000000) - dVar2);
  *(float *)(param_2 + 0x280) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x30) ^ 0x80000000) - dVar2);
  if (FLOAT_803e4ccc < *(float *)(param_1 + 0x12)) {
    *(byte *)(param_2 + 0x29f) = *(byte *)(param_2 + 0x29f) | 1;
  }
  if (FLOAT_803e4ccc < *(float *)(param_1 + 0x16)) {
    *(byte *)(param_2 + 0x29f) = *(byte *)(param_2 + 0x29f) | 2;
  }
  if (FLOAT_803e4ccc < *(float *)(param_2 + 0x278)) {
    *(byte *)(param_2 + 0x29f) = *(byte *)(param_2 + 0x29f) | 4;
  }
  if (FLOAT_803e4ccc < *(float *)(param_2 + 0x27c)) {
    *(byte *)(param_2 + 0x29f) = *(byte *)(param_2 + 0x29f) | 8;
  }
  if (FLOAT_803e4ccc < *(float *)(param_2 + 0x280)) {
    *(byte *)(param_2 + 0x29f) = *(byte *)(param_2 + 0x29f) | 0x10;
  }
  dVar2 = DOUBLE_803e4cd8;
  fVar1 = FLOAT_803e4cd0;
  *(float *)(param_2 + 0x284) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x32) ^ 0x80000000) -
              DOUBLE_803e4cd8) / FLOAT_803e4cd0;
  *(float *)(param_2 + 0x288) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x34) ^ 0x80000000) - dVar2) /
       fVar1;
  *(float *)(param_2 + 0x28c) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x36) ^ 0x80000000) - dVar2) /
       fVar1;
  fVar1 = FLOAT_803e4cd4;
  *(float *)(param_2 + 0x290) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x26) ^ 0x80000000) - dVar2) /
       FLOAT_803e4cd4;
  *(float *)(param_2 + 0x294) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x28) ^ 0x80000000) - dVar2) /
       fVar1;
  *(float *)(param_2 + 0x298) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x2a) ^ 0x80000000) - dVar2) /
       fVar1;
  *(undefined2 *)(param_2 + 0x29c) = 0;
  return;
}

