// Function: FUN_80156708
// Entry: 80156708
// Size: 720 bytes

void FUN_80156708(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  double dVar5;
  
  if (FLOAT_803e3740 < *(float *)(param_10 + 0x328)) {
    *(float *)(param_10 + 0x328) = FLOAT_803e3744;
  }
  *(undefined *)(*(int *)(param_9 + 0x2a) + 0x70) = 0;
  uVar4 = 0;
  FUN_80035eec((int)param_9,10,1,0);
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    FUN_8000bb38((uint)param_9,0x261);
  }
  *(float *)(param_10 + 0x328) = *(float *)(param_10 + 0x328) - FLOAT_803dc074;
  if (*(float *)(param_10 + 0x328) <= FLOAT_803e3730) {
    if ((*(uint *)(param_10 + 0x2dc) & 0x600) == 0) {
      uVar2 = FUN_80022264(600,0x352);
      *(float *)(param_10 + 0x328) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3738);
    }
    else {
      uVar2 = FUN_80022264(0x96,0xfa);
      *(float *)(param_10 + 0x328) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3738);
    }
    FUN_8000bb38((uint)param_9,0x262);
  }
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    FUN_8003042c((double)FLOAT_803e3730,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,3,(uint)*(byte *)(param_10 + 0x323),uVar4,param_13,param_14,param_15,
                 param_16);
  }
  fVar1 = FLOAT_803e3730;
  if (*(float *)(param_10 + 0x324) <= FLOAT_803e3730) {
    if ((*(uint *)(param_10 + 0x2dc) & 0x400) != 0) {
      *(float *)(param_10 + 0x324) = FLOAT_803e3748;
    }
  }
  else {
    *(float *)(param_10 + 0x324) = *(float *)(param_10 + 0x324) - FLOAT_803dc074;
    if (*(float *)(param_10 + 0x324) <= fVar1) {
      *(float *)(param_10 + 0x324) = FLOAT_803e3748;
      *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) | 0x10000;
    }
  }
  if ((*(uint *)(param_10 + 0x2dc) & 0x8000000) == 0) {
    iVar3 = *(int *)(param_10 + 0x29c);
    dVar5 = FUN_8014cfcc((double)*(float *)(iVar3 + 0x18),
                         (double)(FLOAT_803e3750 + *(float *)(iVar3 + 0x1c)),
                         (double)*(float *)(iVar3 + 0x20),(double)FLOAT_803e3754,
                         (double)FLOAT_803e3758,(double)FLOAT_803e375c,
                         (double)*(float *)(param_10 + 0x304),(int)param_9);
  }
  else {
    dVar5 = (double)FLOAT_803e374c;
  }
  if ((((double)FLOAT_803e3730 < dVar5) && (*(float *)(param_9 + 0x14) < FLOAT_803e3760)) ||
     ((*(uint *)(param_10 + 0x2dc) & 0x8000000) != 0)) {
    *(undefined *)(param_10 + 0x33a) = 1;
  }
  if ((*(char *)(param_10 + 0x33a) == '\0') || (dVar5 <= (double)FLOAT_803e3730)) {
    *(undefined *)(param_10 + 0x33a) = 0;
    if (FLOAT_803e3774 < *(float *)(param_10 + 0x308)) {
      *(float *)(param_10 + 0x308) =
           -(FLOAT_803e3778 * FLOAT_803dc074 - *(float *)(param_10 + 0x308));
    }
  }
  else {
    *(float *)(param_10 + 0x308) = FLOAT_803e3764;
    if (*(short *)(param_10 + 0x2b0) != 0) {
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
  FUN_8014d194((double)FLOAT_803e3730,(double)FLOAT_803e3730,param_9,param_10,0x2d,'\0');
  return;
}

