// Function: FUN_802c0fa0
// Entry: 802c0fa0
// Size: 328 bytes

undefined4
FUN_802c0fa0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  float fVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    param_12 = 0;
    *(byte *)(iVar3 + 0xbc0) = *(byte *)(iVar3 + 0xbc0) & 0xef;
    *(float *)(param_9 + 0x28) = FLOAT_803e903c;
    if ((*(byte *)(iVar3 + 0xbc0) >> 5 & 1) != 0) {
      *(byte *)(iVar3 + 0xbc0) = *(byte *)(iVar3 + 0xbc0) & 0xdf;
      FUN_802bf838(param_9,param_10,*(byte *)(iVar3 + 0xbc0) >> 5 & 1);
    }
  }
  sVar1 = *(short *)(param_9 + 0xa0);
  if (sVar1 == 0x20c) {
    if (*(char *)(param_10 + 0x346) != '\0') {
      *(byte *)(iVar3 + 0xad5) = *(byte *)(iVar3 + 0xad5) & 0xfd;
      return 3;
    }
  }
  else if ((sVar1 < 0x20c) && (sVar1 == 0x203)) {
    if (*(short *)(iVar3 + 0xbb0) != 0) {
      FUN_8003042c((double)FLOAT_803e903c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0x20c,0,param_12,param_13,param_14,param_15,param_16);
      *(float *)(param_10 + 0x2a0) = FLOAT_803e90a0;
    }
  }
  else {
    FUN_8003042c((double)FLOAT_803e903c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0x203,0,param_12,param_13,param_14,param_15,param_16);
    *(byte *)(iVar3 + 0xad5) = *(byte *)(iVar3 + 0xad5) | 2;
    fVar2 = FLOAT_803e903c;
    *(float *)(param_10 + 0x294) = FLOAT_803e903c;
    *(float *)(param_10 + 0x284) = fVar2;
    *(float *)(param_10 + 0x280) = fVar2;
    *(float *)(param_9 + 0x24) = fVar2;
    *(float *)(param_9 + 0x28) = fVar2;
    *(float *)(param_9 + 0x2c) = fVar2;
    *(float *)(param_10 + 0x2a0) = FLOAT_803e90a0;
  }
  return 0;
}

