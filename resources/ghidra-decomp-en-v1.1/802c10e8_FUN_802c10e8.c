// Function: FUN_802c10e8
// Entry: 802c10e8
// Size: 228 bytes

undefined4
FUN_802c10e8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  double dVar4;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  *param_10 = *param_10 | 0x200000;
  fVar2 = FLOAT_803e903c;
  if (*(char *)((int)param_10 + 0x27a) != '\0') {
    dVar4 = (double)FLOAT_803e903c;
    param_10[0xa5] = (uint)FLOAT_803e903c;
    param_10[0xa1] = (uint)fVar2;
    param_10[0xa0] = (uint)fVar2;
    *(float *)(param_9 + 0x24) = fVar2;
    *(float *)(param_9 + 0x28) = fVar2;
    *(float *)(param_9 + 0x2c) = fVar2;
    *(undefined2 *)(param_10 + 0xce) = 0;
    param_10[0xa8] = (uint)FLOAT_803e908c;
    param_10[0xae] = (uint)FLOAT_803e9090;
    if (*(short *)(param_9 + 0xa0) != 0) {
      FUN_8003042c(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,0,0,
                   param_12,param_13,param_14,param_15,param_16);
    }
    bVar1 = *(byte *)(iVar3 + 0xbc0);
    if ((bVar1 >> 5 & 1) != 0) {
      *(byte *)(iVar3 + 0xbc0) = bVar1 & 0xdf;
      *(undefined *)((int)param_10 + 0x25f) = 0;
    }
  }
  if ((float)param_10[0xa6] < FLOAT_803e9054) {
    *(undefined2 *)(param_10 + 0xcd) = 0;
    *(undefined2 *)((int)param_10 + 0x336) = 0;
    param_10[0xa6] = (uint)FLOAT_803e903c;
  }
  return 0;
}

