// Function: FUN_802b9eec
// Entry: 802b9eec
// Size: 356 bytes

undefined4
FUN_802b9eec(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  iVar4 = *(int *)(param_9 + 0x54);
  *param_10 = *param_10 | 0x200000;
  fVar1 = FLOAT_803e8ecc;
  dVar5 = (double)FLOAT_803e8ecc;
  param_10[0xa5] = (uint)FLOAT_803e8ecc;
  param_10[0xa1] = (uint)fVar1;
  param_10[0xa0] = (uint)fVar1;
  *(float *)(param_9 + 0x24) = fVar1;
  *(float *)(param_9 + 0x28) = fVar1;
  *(float *)(param_9 + 0x2c) = fVar1;
  if (*(char *)((int)param_10 + 0x27a) != '\0') {
    *(byte *)(iVar3 + 0xa8e) = *(byte *)(iVar3 + 0xa8e) & 0xf7;
    *(ushort *)(iVar4 + 0x60) = *(ushort *)(iVar4 + 0x60) | 0x200;
    FUN_8003042c(dVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,0x204,0,
                 param_12,param_13,param_14,param_15,param_16);
    param_10[0xa8] = (uint)FLOAT_803e8ed0;
    FUN_8000bb38(param_9,0x3b3);
  }
  if (((*(ushort *)(iVar4 + 0x60) & 0x200) != 0) && ((*(byte *)(iVar4 + 0xad) & 2) != 0)) {
    *(byte *)(iVar3 + 0xa8e) = *(byte *)(iVar3 + 0xa8e) | 8;
  }
  if ((*(byte *)(iVar3 + 0xa8e) & 8) == 0) {
    *(undefined *)(iVar4 + 0x6e) = 0xb;
    *(undefined *)(iVar4 + 0x6f) = 1;
    *(ushort *)(iVar4 + 0x60) = *(ushort *)(iVar4 + 0x60) | 0x200;
  }
  else {
    *(undefined *)(iVar4 + 0x6e) = 0;
    *(undefined *)(iVar4 + 0x6f) = 0;
    *(ushort *)(iVar4 + 0x60) = *(ushort *)(iVar4 + 0x60) & 0xfdff;
  }
  if (*(float *)(param_9 + 0x98) <= FLOAT_803e8ed4) {
    uVar2 = 0;
  }
  else {
    uVar2 = 8;
  }
  return uVar2;
}

