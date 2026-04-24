// Function: FUN_802402ec
// Entry: 802402ec
// Size: 152 bytes

void FUN_802402ec(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  
  iVar1 = *(int *)(param_9 + 0xb8);
  *(undefined *)(iVar1 + 0x22) = *(undefined *)(param_10 + 0x1b);
  *(undefined *)(iVar1 + 0x24) = 0xff;
  *(undefined *)(iVar1 + 0x25) = 0xf;
  *(undefined *)(iVar1 + 0x27) = 5;
  *(undefined *)(iVar1 + 0x23) = 3;
  *(undefined *)(iVar1 + 0x24) = 3;
  iVar1 = *(int *)(param_9 + 0xb8);
  FUN_8003042c((double)FLOAT_803e8244,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               param_9,4,0,param_12,param_13,param_14,param_15,param_16);
  *(undefined4 *)(iVar1 + 0x14) = DAT_8032ced8;
  *(float *)(param_9 + 0x98) = FLOAT_803e8248;
  FUN_80035a58(param_9,4);
  return;
}

