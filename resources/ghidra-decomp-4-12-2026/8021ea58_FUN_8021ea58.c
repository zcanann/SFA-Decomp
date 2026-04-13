// Function: FUN_8021ea58
// Entry: 8021ea58
// Size: 220 bytes

undefined4
FUN_8021ea58(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  undefined4 uVar2;
  double dVar3;
  
  fVar1 = FLOAT_803e7740;
  dVar3 = (double)FLOAT_803e7740;
  param_10[0xa5] = (uint)FLOAT_803e7740;
  param_10[0xa1] = (uint)fVar1;
  param_10[0xa0] = (uint)fVar1;
  *(float *)(param_9 + 0x24) = fVar1;
  *(float *)(param_9 + 0x28) = fVar1;
  *(float *)(param_9 + 0x2c) = fVar1;
  *param_10 = *param_10 | 0x200000;
  if (*(char *)((int)param_10 + 0x27a) != '\0') {
    *(undefined2 *)(param_10 + 0xce) = 0;
    param_10[0xa8] = (uint)FLOAT_803e77bc;
    param_10[0xae] = (uint)FLOAT_803e77c0;
    if ((int)*(short *)(param_9 + 0xa0) != (int)DAT_803dcf94) {
      FUN_8003042c(dVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                   (int)DAT_803dcf94,0,param_12,param_13,param_14,param_15,param_16);
    }
  }
  if ((float)param_10[0xa6] < FLOAT_803e77c4) {
    *(undefined2 *)(param_10 + 0xcd) = 0;
    *(undefined2 *)((int)param_10 + 0x336) = 0;
    param_10[0xa6] = (uint)FLOAT_803e7740;
  }
  if (((float)param_10[0xa7] <= FLOAT_803e7740) || ((float)param_10[0xa6] <= FLOAT_803e7740)) {
    uVar2 = 0;
  }
  else {
    uVar2 = 3;
  }
  return uVar2;
}

