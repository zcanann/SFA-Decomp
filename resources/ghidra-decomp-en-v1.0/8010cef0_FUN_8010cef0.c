// Function: FUN_8010cef0
// Entry: 8010cef0
// Size: 936 bytes

void FUN_8010cef0(undefined2 *param_1)

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
    uVar5 = FUN_801eed24(iVar6);
  }
  if (uVar5 != *(byte *)(DAT_803dd570 + 10)) {
    fVar3 = FLOAT_803e1948;
    if ((uVar5 == 2) ||
       (fVar1 = FLOAT_803e1950, fVar2 = FLOAT_803e1954, fVar3 = FLOAT_803e194c, uVar5 == 5)) {
      fVar1 = FLOAT_803e1958;
      fVar2 = DAT_803dd570[1];
    }
    *(char *)(DAT_803dd570 + 10) = (char)uVar5;
    DAT_803dd570[6] = fVar3 - DAT_803dd570[3];
    DAT_803dd570[4] = DAT_803dd570[3];
    DAT_803dd570[9] = fVar1 - (DAT_803dd570[7] + fVar2);
    DAT_803dd570[8] = DAT_803dd570[7];
    DAT_803dd570[5] = FLOAT_803e1954;
  }
  fVar3 = FLOAT_803e195c;
  if (DAT_803dd570[5] < FLOAT_803e195c) {
    DAT_803dd570[5] = FLOAT_803e1960 * FLOAT_803db414 + DAT_803dd570[5];
    if (fVar3 < DAT_803dd570[5]) {
      DAT_803dd570[5] = fVar3;
    }
    DAT_803dd570[3] = DAT_803dd570[5] * DAT_803dd570[6] + DAT_803dd570[4];
    DAT_803dd570[7] = DAT_803dd570[5] * DAT_803dd570[9] + DAT_803dd570[8];
  }
  dVar4 = DOUBLE_803e1988;
  if ((uVar5 == 2) || (uVar5 == 5)) {
    *DAT_803dd570 =
         -(((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 4) ^ 0x80000000) -
                   DOUBLE_803e1988) / FLOAT_803e1964) * FLOAT_803db414 - *DAT_803dd570);
    DAT_803dd570[1] =
         -(((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 2) ^ 0x80000000) - dVar4) /
           FLOAT_803e1968) * FLOAT_803db414 - DAT_803dd570[1]);
    fVar3 = FLOAT_803e196c;
    *DAT_803dd570 = -(FLOAT_803e196c * *DAT_803dd570 * FLOAT_803db414 - *DAT_803dd570);
    DAT_803dd570[1] = -(fVar3 * DAT_803dd570[1] * FLOAT_803db414 - DAT_803dd570[1]);
    *(float *)(param_1 + 0xe) = DAT_803dd570[1] + *(float *)(iVar6 + 0x1c) + DAT_803dd570[7];
  }
  else {
    *DAT_803dd570 =
         -(((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 4) ^ 0x80000000) -
                   DOUBLE_803e1988) / FLOAT_803e1964) * FLOAT_803db414 - *DAT_803dd570);
    DAT_803dd570[1] =
         -(((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 2) ^ 0x80000000) - dVar4) /
           FLOAT_803e1968) * FLOAT_803db414 - DAT_803dd570[1]);
    fVar3 = FLOAT_803e196c;
    *DAT_803dd570 = -(FLOAT_803e196c * *DAT_803dd570 * FLOAT_803db414 - *DAT_803dd570);
    DAT_803dd570[1] = -(fVar3 * DAT_803dd570[1] * FLOAT_803db414 - DAT_803dd570[1]);
    *(float *)(param_1 + 0xe) = DAT_803dd570[1] + *(float *)(iVar6 + 0x1c) + DAT_803dd570[7];
  }
  *(float *)(param_1 + 0xc) = FLOAT_803e1970 + *(float *)(iVar6 + 0x18) + DAT_803dd570[2];
  *(float *)(param_1 + 0x10) = *(float *)(iVar6 + 0x20) + *DAT_803dd570;
  param_1[1] = 0x708;
  *param_1 = 0x4000;
  param_1[2] = (short)(-(int)*(short *)(iVar6 + 4) >> 3);
  *(float *)(param_1 + 0x5a) = FLOAT_803e1974;
  fVar3 = (DAT_803dd570[3] - DAT_803dd570[2]) / FLOAT_803e1978;
  fVar1 = FLOAT_803e197c;
  if ((fVar3 <= FLOAT_803e197c) && (fVar1 = fVar3, fVar3 < FLOAT_803e1980)) {
    fVar1 = FLOAT_803e1980;
  }
  DAT_803dd570[2] = DAT_803dd570[2] + fVar1 * FLOAT_803db414;
  FUN_8000e034((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
               (double)*(float *)(param_1 + 0x10),param_1 + 6,param_1 + 8,param_1 + 10,
               *(undefined4 *)(param_1 + 0x18));
  return;
}

