// Function: FUN_8010d18c
// Entry: 8010d18c
// Size: 936 bytes

void FUN_8010d18c(undefined2 *param_1)

{
  float fVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  uint uVar5;
  int iVar6;
  
  uVar5 = 0;
  iVar6 = *(int *)(param_1 + 0x52);
  if (iVar6 != 0) {
    uVar5 = FUN_801ef35c(iVar6);
  }
  if (uVar5 != *(byte *)(DAT_803de1e8 + 10)) {
    fVar3 = FLOAT_803e25c8;
    if ((uVar5 == 2) ||
       (fVar1 = FLOAT_803e25d0, fVar2 = FLOAT_803e25d4, fVar3 = FLOAT_803e25cc, uVar5 == 5)) {
      fVar1 = FLOAT_803e25d8;
      fVar2 = DAT_803de1e8[1];
    }
    *(char *)(DAT_803de1e8 + 10) = (char)uVar5;
    DAT_803de1e8[6] = fVar3 - DAT_803de1e8[3];
    DAT_803de1e8[4] = DAT_803de1e8[3];
    DAT_803de1e8[9] = fVar1 - (DAT_803de1e8[7] + fVar2);
    DAT_803de1e8[8] = DAT_803de1e8[7];
    DAT_803de1e8[5] = FLOAT_803e25d4;
  }
  fVar3 = FLOAT_803e25dc;
  if (DAT_803de1e8[5] < FLOAT_803e25dc) {
    DAT_803de1e8[5] = FLOAT_803e25e0 * FLOAT_803dc074 + DAT_803de1e8[5];
    if (fVar3 < DAT_803de1e8[5]) {
      DAT_803de1e8[5] = fVar3;
    }
    DAT_803de1e8[3] = DAT_803de1e8[5] * DAT_803de1e8[6] + DAT_803de1e8[4];
    DAT_803de1e8[7] = DAT_803de1e8[5] * DAT_803de1e8[9] + DAT_803de1e8[8];
  }
  dVar4 = DOUBLE_803e2608;
  if ((uVar5 == 2) || (uVar5 == 5)) {
    *DAT_803de1e8 =
         -(((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 4) ^ 0x80000000) -
                   DOUBLE_803e2608) / FLOAT_803e25e4) * FLOAT_803dc074 - *DAT_803de1e8);
    DAT_803de1e8[1] =
         -(((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 2) ^ 0x80000000) - dVar4) /
           FLOAT_803e25e8) * FLOAT_803dc074 - DAT_803de1e8[1]);
    fVar3 = FLOAT_803e25ec;
    *DAT_803de1e8 = -(FLOAT_803e25ec * *DAT_803de1e8 * FLOAT_803dc074 - *DAT_803de1e8);
    DAT_803de1e8[1] = -(fVar3 * DAT_803de1e8[1] * FLOAT_803dc074 - DAT_803de1e8[1]);
    *(float *)(param_1 + 0xe) = DAT_803de1e8[1] + *(float *)(iVar6 + 0x1c) + DAT_803de1e8[7];
  }
  else {
    *DAT_803de1e8 =
         -(((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 4) ^ 0x80000000) -
                   DOUBLE_803e2608) / FLOAT_803e25e4) * FLOAT_803dc074 - *DAT_803de1e8);
    DAT_803de1e8[1] =
         -(((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 2) ^ 0x80000000) - dVar4) /
           FLOAT_803e25e8) * FLOAT_803dc074 - DAT_803de1e8[1]);
    fVar3 = FLOAT_803e25ec;
    *DAT_803de1e8 = -(FLOAT_803e25ec * *DAT_803de1e8 * FLOAT_803dc074 - *DAT_803de1e8);
    DAT_803de1e8[1] = -(fVar3 * DAT_803de1e8[1] * FLOAT_803dc074 - DAT_803de1e8[1]);
    *(float *)(param_1 + 0xe) = DAT_803de1e8[1] + *(float *)(iVar6 + 0x1c) + DAT_803de1e8[7];
  }
  *(float *)(param_1 + 0xc) = FLOAT_803e25f0 + *(float *)(iVar6 + 0x18) + DAT_803de1e8[2];
  *(float *)(param_1 + 0x10) = *(float *)(iVar6 + 0x20) + *DAT_803de1e8;
  param_1[1] = 0x708;
  *param_1 = 0x4000;
  param_1[2] = (short)(-(int)*(short *)(iVar6 + 4) >> 3);
  *(float *)(param_1 + 0x5a) = FLOAT_803e25f4;
  fVar3 = (DAT_803de1e8[3] - DAT_803de1e8[2]) / FLOAT_803e25f8;
  fVar1 = FLOAT_803e25fc;
  if ((fVar3 <= FLOAT_803e25fc) && (fVar1 = fVar3, fVar3 < FLOAT_803e2600)) {
    fVar1 = FLOAT_803e2600;
  }
  DAT_803de1e8[2] = DAT_803de1e8[2] + fVar1 * FLOAT_803dc074;
  FUN_8000e054((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
               (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
               (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
  return;
}

