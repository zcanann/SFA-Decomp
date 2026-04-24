// Function: FUN_801e38f4
// Entry: 801e38f4
// Size: 268 bytes

void FUN_801e38f4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  int iVar2;
  double dVar3;
  
  fVar1 = FLOAT_803e6504;
  if (*(int *)(param_9 + 0x30) != 0) {
    iVar2 = *(int *)(*(int *)(param_9 + 0x30) + 0xf4);
    dVar3 = (double)FLOAT_803e6504;
    *(float *)(param_9 + 0xc) = FLOAT_803e6504;
    *(float *)(param_9 + 0x10) = fVar1;
    *(float *)(param_9 + 0x14) = fVar1;
    if (*(short *)(*(int *)(param_9 + 0x30) + 0x46) == 0x139) {
      if ((iVar2 < 10) || (0xc < iVar2)) {
        if (*(short *)(param_9 + 0xa0) != 1) {
          FUN_8003042c((double)FLOAT_803e6504,param_2,param_3,param_4,param_5,param_6,param_7,
                       param_8,param_9,1,0,param_12,param_13,param_14,param_15,param_16);
        }
        dVar3 = (double)FLOAT_803e6510;
      }
      else {
        if (*(short *)(param_9 + 0xa0) != 0) {
          FUN_8003042c(dVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,0,0,
                       param_12,param_13,param_14,param_15,param_16);
        }
        if (iVar2 < 0xc) {
          dVar3 = (double)FLOAT_803e650c;
        }
        else {
          dVar3 = (double)FLOAT_803e6508;
        }
      }
    }
    else {
      if (*(short *)(param_9 + 0xa0) != 1) {
        FUN_8003042c(dVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,1,0,
                     param_12,param_13,param_14,param_15,param_16);
      }
      dVar3 = (double)FLOAT_803e6510;
    }
    FUN_8002fb40(dVar3,(double)(float)((double)CONCAT44(0x43300000,(uint)DAT_803dc070) -
                                      DOUBLE_803e6518));
  }
  return;
}

