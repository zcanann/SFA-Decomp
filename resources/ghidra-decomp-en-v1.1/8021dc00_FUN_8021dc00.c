// Function: FUN_8021dc00
// Entry: 8021dc00
// Size: 400 bytes

undefined4
FUN_8021dc00(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  float fVar2;
  undefined4 uVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_9 + 0xb8);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    *(float *)(iVar4 + 0xc30) = FLOAT_803e774c;
    fVar2 = FLOAT_803e7740;
    *(float *)(param_10 + 0x294) = FLOAT_803e7740;
    *(float *)(param_10 + 0x284) = fVar2;
    *(float *)(param_10 + 0x280) = fVar2;
    *(float *)(param_9 + 0x24) = fVar2;
    *(float *)(param_9 + 0x28) = fVar2;
    *(float *)(param_9 + 0x2c) = fVar2;
  }
  if (*(char *)(param_10 + 0x346) != '\0') {
    sVar1 = *(short *)(param_9 + 0xa0);
    if (sVar1 == 10) {
      if ((double)*(float *)(param_10 + 0x2a0) <= (double)FLOAT_803e7740) {
        return 8;
      }
      FUN_8003042c((double)FLOAT_803e7740,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,5,0,param_12,param_13,param_14,param_15,param_16);
    }
    else if ((sVar1 < 10) && (sVar1 == 5)) {
      if (*(float *)(iVar4 + 0xc30) < FLOAT_803e7740) {
        FUN_8003042c((double)FLOAT_803e7750,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,10,0,param_12,param_13,param_14,param_15,param_16);
        *(float *)(param_10 + 0x2a0) = FLOAT_803e7754;
      }
    }
    else {
      FUN_8003042c((double)FLOAT_803e7740,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,10,0,param_12,param_13,param_14,param_15,param_16);
      *(float *)(param_10 + 0x2a0) = FLOAT_803e7758;
    }
  }
  if (((*(short *)(param_9 + 0xa0) != 10) ||
      ((double)FLOAT_803e7740 <= (double)*(float *)(param_10 + 0x2a0))) ||
     ((double)FLOAT_803e775c <= (double)*(float *)(param_9 + 0x98))) {
    *(float *)(iVar4 + 0xc30) =
         *(float *)(iVar4 + 0xc30) -
         (float)((double)CONCAT44(0x43300000,(uint)DAT_803dc070) - DOUBLE_803e7768);
    uVar3 = 0;
  }
  else {
    FUN_8003042c((double)FLOAT_803e7740,(double)*(float *)(param_9 + 0x98),param_3,param_4,param_5,
                 param_6,param_7,param_8,param_9,0,0,param_12,param_13,param_14,param_15,param_16);
    *(float *)(param_10 + 0x2a0) = FLOAT_803e7760;
    uVar3 = 8;
  }
  return uVar3;
}

