// Function: FUN_801dcd5c
// Entry: 801dcd5c
// Size: 352 bytes

void FUN_801dcd5c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_9 + 0x5c);
  *(float *)(iVar3 + 0x34) = FLOAT_803e622c;
  fVar1 = FLOAT_803e6228;
  *(float *)(iVar3 + 0x30) = FLOAT_803e6228;
  *(ushort *)(iVar3 + 0x48) = (ushort)*(byte *)(param_10 + 0x1b) << 1;
  *(undefined *)(iVar3 + 0x4c) = *(undefined *)(param_10 + 0x23);
  *(float *)(iVar3 + 0x3c) = fVar1;
  *(undefined4 *)(iVar3 + 0x38) = *(undefined4 *)(param_10 + 0x1c);
  param_9[2] = (*(byte *)(param_10 + 0x18) - 0x7f) * 0x80;
  param_9[1] = (*(byte *)(param_10 + 0x19) - 0x7f) * 0x80;
  *param_9 = (ushort)*(byte *)(param_10 + 0x1a) << 8;
  *(float *)(param_9 + 4) = FLOAT_803e6250 * *(float *)(param_10 + 0x1c);
  param_9[0x7c] = 0;
  param_9[0x7d] = 0;
  param_9[0x58] = param_9[0x58] | 0x2000;
  uVar2 = FUN_80022264(1,99);
  FUN_8003042c((double)((float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e6260) /
                       FLOAT_803e6254),param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               param_9,0,0,param_12,param_13,param_14,param_15,param_16);
  FUN_8002fb40((double)FLOAT_803e6224,(double)FLOAT_803e6224);
  FUN_80035c48((int)param_9,(short)(int)(FLOAT_803e6258 * *(float *)(iVar3 + 0x38)),-5,0xff);
  if ((*(byte *)(iVar3 + 0x4c) & 0x80) != 0) {
    *(byte *)(iVar3 + 0x4c) = *(byte *)(iVar3 + 0x4c) | 0x20;
  }
  return;
}

