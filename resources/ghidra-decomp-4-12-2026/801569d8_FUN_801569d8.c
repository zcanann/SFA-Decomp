// Function: FUN_801569d8
// Entry: 801569d8
// Size: 892 bytes

void FUN_801569d8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,undefined4 *param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  uint uVar2;
  char cVar3;
  undefined4 uVar4;
  int iVar5;
  float *pfVar6;
  double dVar7;
  
  pfVar6 = (float *)*param_10;
  iVar5 = *(int *)(param_9 + 0x26);
  *(undefined *)(*(int *)(param_9 + 0x2a) + 0x70) = 0;
  uVar4 = 0;
  FUN_80035eec((int)param_9,10,1,0);
  if ((param_10[0xb7] & 0x40000000) != 0) {
    FUN_8000bb38((uint)param_9,0x261);
  }
  param_10[0xca] = (float)param_10[0xca] - FLOAT_803dc074;
  if ((float)param_10[0xca] <= FLOAT_803e3730) {
    if ((param_10[0xb7] & 0x600) == 0) {
      uVar2 = FUN_80022264(600,0x352);
      param_10[0xca] = (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3738);
    }
    else {
      uVar2 = FUN_80022264(0x96,0xfa);
      param_10[0xca] = (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3738);
    }
    FUN_8000bb38((uint)param_9,0x262);
  }
  if ((param_10[0xb7] & 0x40000000) != 0) {
    FUN_8003042c((double)FLOAT_803e3730,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,(uint)*(byte *)((int)param_10 + 0x323),uVar4,param_13,param_14,param_15,
                 param_16);
  }
  fVar1 = FLOAT_803e3730;
  if ((float)param_10[0xc9] <= FLOAT_803e3730) {
    param_10[0xb9] = param_10[0xb9] & 0xfffeffff;
  }
  else {
    param_10[0xc9] = (float)param_10[0xc9] - FLOAT_803dc074;
    if ((float)param_10[0xc9] <= fVar1) {
      param_10[0xc9] = fVar1;
    }
  }
  if ((param_10[0xb7] & 0x2000) == 0) {
    if ((param_10[0xb7] & 0x8000000) == 0) {
      dVar7 = FUN_8014cfcc((double)*(float *)(iVar5 + 8),(double)*(float *)(iVar5 + 0xc),
                           (double)*(float *)(iVar5 + 0x10),(double)FLOAT_803e3754,
                           (double)FLOAT_803e3758,(double)FLOAT_803e375c,
                           (double)(float)param_10[0xc1],(int)param_9);
    }
    else {
      dVar7 = (double)FLOAT_803e3754;
    }
  }
  else {
    iVar5 = FUN_80010340((double)(float)param_10[0xbf],pfVar6);
    if ((((iVar5 != 0) || (pfVar6[4] != 0.0)) &&
        (cVar3 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar6), cVar3 != '\0')) &&
       (cVar3 = (**(code **)(*DAT_803dd71c + 0x8c))
                          ((double)FLOAT_803e377c,*param_10,param_9,&DAT_803dc940,0xffffffff),
       cVar3 != '\0')) {
      param_10[0xb7] = param_10[0xb7] & 0xffffdfff;
    }
    if ((param_10[0xb7] & 0x8000000) == 0) {
      dVar7 = FUN_8014cfcc((double)pfVar6[0x1a],(double)pfVar6[0x1b],(double)pfVar6[0x1c],
                           (double)FLOAT_803e3754,(double)FLOAT_803e3758,(double)FLOAT_803e375c,
                           (double)(float)param_10[0xc1],(int)param_9);
    }
    else {
      dVar7 = (double)FLOAT_803e3754;
    }
  }
  if ((((double)FLOAT_803e3730 < dVar7) && (*(float *)(param_9 + 0x14) < FLOAT_803e3760)) ||
     ((param_10[0xb7] & 0x8000000) != 0)) {
    *(undefined *)((int)param_10 + 0x33a) = 1;
  }
  if ((*(char *)((int)param_10 + 0x33a) == '\0') || (dVar7 <= (double)FLOAT_803e3730)) {
    *(undefined *)((int)param_10 + 0x33a) = 0;
    if (FLOAT_803e3774 < (float)param_10[0xc2]) {
      param_10[0xc2] = -(FLOAT_803e3778 * FLOAT_803dc074 - (float)param_10[0xc2]);
    }
  }
  else {
    param_10[0xc2] = FLOAT_803e3764;
    if (*(short *)(param_10 + 0xac) != 0) {
      *(float *)(param_9 + 0x14) = *(float *)(param_9 + 0x14) + FLOAT_803e3768;
    }
    if (FLOAT_803e376c <= *(float *)(param_9 + 0x14)) {
      if (FLOAT_803e3770 < *(float *)(param_9 + 0x14)) {
        *(float *)(param_9 + 0x14) = FLOAT_803e3770;
      }
    }
    else {
      *(float *)(param_9 + 0x14) = FLOAT_803e376c;
    }
  }
  FUN_8014d194((double)FLOAT_803e3730,(double)FLOAT_803e3730,param_9,(int)param_10,0x2d,'\0');
  return;
}

