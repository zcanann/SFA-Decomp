// Function: FUN_802ba720
// Entry: 802ba720
// Size: 532 bytes

undefined4
FUN_802ba720(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  int iVar2;
  undefined4 uVar3;
  uint uVar4;
  int iVar5;
  double dVar6;
  float local_18 [2];
  
  local_18[0] = FLOAT_803e8ed8;
  iVar2 = FUN_80036f50(0x13,param_9,local_18);
  iVar5 = *(int *)(param_9 + 0xb8);
  *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
  fVar1 = FLOAT_803e8ecc;
  dVar6 = (double)FLOAT_803e8ecc;
  param_10[0xa5] = (uint)FLOAT_803e8ecc;
  param_10[0xa1] = (uint)fVar1;
  param_10[0xa0] = (uint)fVar1;
  *(float *)(param_9 + 0x24) = fVar1;
  *(float *)(param_9 + 0x28) = fVar1;
  *(float *)(param_9 + 0x2c) = fVar1;
  *param_10 = *param_10 | 0x200000;
  if (*(char *)((int)param_10 + 0x27a) != '\0') {
    *(undefined2 *)(param_10 + 0xce) = 0;
    param_10[0xa8] = (uint)FLOAT_803e8f14;
    param_10[0xae] = (uint)FLOAT_803e8f1c;
    if ((int)*(short *)(param_9 + 0xa0) != (int)DAT_803dd3b0) {
      FUN_8003042c(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                   (int)DAT_803dd3b0,0,param_12,param_13,param_14,param_15,param_16);
    }
  }
  if (((*(short *)(param_9 + 0xa0) < 0x20b) && (0x208 < *(short *)(param_9 + 0xa0))) &&
     (*(char *)((int)param_10 + 0x346) != '\0')) {
    FUN_8003042c((double)FLOAT_803e8ecc,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,(int)DAT_803dd3b0,0,param_12,param_13,param_14,param_15,param_16);
    param_10[0xa8] = (uint)FLOAT_803e8f14;
  }
  if ((float)param_10[0xa6] < FLOAT_803e8ee4) {
    *(undefined2 *)(param_10 + 0xcd) = 0;
    *(undefined2 *)((int)param_10 + 0x336) = 0;
    param_10[0xa6] = (uint)FLOAT_803e8ecc;
  }
  if ((((float)param_10[0xa7] <= FLOAT_803e8ecc) || ((float)param_10[0xa6] <= FLOAT_803e8ecc)) ||
     (*(short *)(param_10 + 0xcd) < *(short *)(iVar5 + 0xa86))) {
    if ((((float)param_10[0xa7] <= FLOAT_803e8f20) || ((float)param_10[0xa6] <= FLOAT_803e8f20)) ||
       (*(short *)(iVar5 + 0xa86) <= *(short *)(param_10 + 0xcd))) {
      if (((param_10[199] & 0x100) == 0) || ((iVar2 != 0 && ((*(byte *)(iVar2 + 0xaf) & 4) != 0))))
      {
        uVar4 = FUN_80020078(0x3e3);
        if ((uVar4 != 0) &&
           (uVar4 = FUN_80022150((double)FLOAT_803e8edc,(double)FLOAT_803e8ee0,
                                 (float *)(iVar5 + 0xd04)), uVar4 != 0)) {
          FUN_8000bb38(param_9,0x43a);
        }
        uVar3 = 0;
      }
      else {
        uVar3 = 0xc;
      }
    }
    else {
      uVar3 = 0xb;
    }
  }
  else {
    uVar3 = 10;
  }
  return uVar3;
}

