// Function: FUN_80165e64
// Entry: 80165e64
// Size: 388 bytes

undefined4
FUN_80165e64(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  double dVar2;
  
  iVar1 = *(int *)(*(int *)(param_9 + 0x5c) + 0x40c);
  *(undefined *)((int)param_10 + 0x34d) = 1;
  if (*(char *)((int)param_10 + 0x27a) != '\0') {
    *(float *)(iVar1 + 0x60) = FLOAT_803e3c9c;
    FUN_80036018((int)param_9);
    dVar2 = (double)FUN_80293bc4();
    *(float *)(param_9 + 0x12) = (float)(-(double)*(float *)(iVar1 + 0x60) * dVar2);
    *(float *)(param_9 + 0x14) = FLOAT_803e3c74;
    dVar2 = (double)FUN_802940dc();
    *(float *)(param_9 + 0x16) = (float)(-(double)*(float *)(iVar1 + 0x60) * dVar2);
    *param_10 = *param_10 | 0x2004000;
    FUN_8003042c((double)FLOAT_803e3c74,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
    *(float *)(iVar1 + 0x44) = FLOAT_803e3c74;
  }
  FUN_80035eec((int)param_9,9,1,-1);
  *(undefined *)(*(int *)(param_9 + 0x2a) + 0x6c) = 9;
  *(undefined *)(*(int *)(param_9 + 0x2a) + 0x6d) = 1;
  FUN_80033a34(param_9);
  (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,param_9,param_10 + 1);
  if (*(char *)((int)param_10 + 0x27a) != '\0') {
    if (*(char *)(iVar1 + 0x90) == '\x06') {
      if ((*(byte *)(iVar1 + 0x92) >> 2 & 1) == 0) {
        FUN_801668f0((int)param_9,iVar1);
      }
      else {
        FUN_80165fe8((int)param_9,iVar1);
      }
    }
    else {
      FUN_80166138(param_9,iVar1);
    }
  }
  return 0;
}

