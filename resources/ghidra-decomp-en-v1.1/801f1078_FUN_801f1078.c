// Function: FUN_801f1078
// Entry: 801f1078
// Size: 156 bytes

void FUN_801f1078(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  
  iVar1 = *(int *)(param_9 + 0x5c);
  FUN_80037a5c((int)param_9,4);
  *(undefined **)(param_9 + 0x5e) = &LAB_801f0f38;
  *param_9 = (short)((int)*(char *)(param_10 + 0x18) << 8);
  param_9[1] = *(undefined2 *)(param_10 + 0x1c);
  *(short *)(iVar1 + 4) = (short)*(char *)(param_10 + 0x19);
  *(undefined2 *)(iVar1 + 6) = *(undefined2 *)(param_10 + 0x1a);
  FUN_8003042c((double)FLOAT_803e69a0,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               param_9,*(short *)(iVar1 + 4) + 0x100,0,param_12,param_13,param_14,param_15,param_16)
  ;
  return;
}

