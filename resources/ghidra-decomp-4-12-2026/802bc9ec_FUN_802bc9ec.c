// Function: FUN_802bc9ec
// Entry: 802bc9ec
// Size: 240 bytes

undefined4
FUN_802bc9ec(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  double dVar4;
  
  fVar1 = FLOAT_803e8f58;
  iVar3 = *(int *)(param_9 + 0xb8);
  dVar4 = (double)FLOAT_803e8f58;
  param_10[0xa5] = (uint)FLOAT_803e8f58;
  param_10[0xa1] = (uint)fVar1;
  param_10[0xa0] = (uint)fVar1;
  *(float *)(param_9 + 0x24) = fVar1;
  *(float *)(param_9 + 0x28) = fVar1;
  *(float *)(param_9 + 0x2c) = fVar1;
  *param_10 = *param_10 | 0x200000;
  if (*(char *)((int)param_10 + 0x27a) != '\0') {
    param_10[0xa8] = (uint)FLOAT_803e8f5c;
    if (*(short *)(param_9 + 0xa0) != 5) {
      FUN_8003042c(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,5,0,
                   param_12,param_13,param_14,param_15,param_16);
    }
    uVar2 = FUN_80022264(0x4b0,0x960);
    *(short *)(iVar3 + 0x38c) = (short)uVar2;
  }
  if ((*(byte *)(param_9 + 0xaf) & 1) != 0) {
    FUN_800201ac(0x223,1);
    FUN_80014b68(0,0x100);
  }
  uVar2 = FUN_80022150((double)FLOAT_803e8f60,(double)FLOAT_803e8f64,(float *)(iVar3 + 0x600));
  if (uVar2 != 0) {
    FUN_8000bb38(param_9,0x43a);
  }
  return 0;
}

