// Function: FUN_802ba598
// Entry: 802ba598
// Size: 392 bytes

undefined4
FUN_802ba598(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  *param_10 = *param_10 | 0x200000;
  *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
  sVar1 = *(short *)(param_9 + 0xa0);
  if (sVar1 == 0x206) {
    if (*(char *)((int)param_10 + 0x346) != '\0') {
      if ((double)(float)param_10[0xa8] <= (double)FLOAT_803e8ecc) {
        return 8;
      }
      FUN_8003042c((double)FLOAT_803e8ecc,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0x205,0,param_12,param_13,param_14,param_15,param_16);
      param_10[0xa8] = (uint)FLOAT_803e8f14;
    }
    if (((*(short *)(iVar2 + 0xa88) != 0) && (FLOAT_803e8ecc < (float)param_10[0xa8])) &&
       ((param_10[199] != 0 ||
        ((FLOAT_803e8ecc != (float)param_10[0xa4] || (FLOAT_803e8ecc != (float)param_10[0xa3]))))))
    {
      param_10[0xa8] = (uint)-(float)param_10[0xa8];
    }
  }
  else {
    if (sVar1 < 0x206) {
      if (0x204 < sVar1) {
        if (*(short *)(iVar2 + 0xa88) == 0) {
          return 0;
        }
        if (((param_10[199] == 0) && (FLOAT_803e8ecc == (float)param_10[0xa4])) &&
           (FLOAT_803e8ecc == (float)param_10[0xa3])) {
          return 0;
        }
        FUN_8003042c((double)FLOAT_803e8ecc,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0x207,0,param_12,param_13,param_14,param_15,param_16);
        param_10[0xa8] = (uint)FLOAT_803e8f18;
        return 0;
      }
    }
    else if (sVar1 < 0x208) {
      if (*(char *)((int)param_10 + 0x346) == '\0') {
        return 0;
      }
      return 8;
    }
    FUN_8003042c((double)FLOAT_803e8ecc,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0x206,0,param_12,param_13,param_14,param_15,param_16);
    param_10[0xa8] = (uint)FLOAT_803e8f18;
  }
  return 0;
}

