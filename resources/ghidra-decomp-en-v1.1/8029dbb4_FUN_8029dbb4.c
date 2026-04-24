// Function: FUN_8029dbb4
// Entry: 8029dbb4
// Size: 108 bytes

undefined4
FUN_8029dbb4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  undefined4 uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  *(undefined *)(param_10 + 0x34d) = 3;
  if (**(char **)(iVar2 + 0x35c) < '\x01') {
    uVar1 = 0;
  }
  else {
    FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,200,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined4 *)(param_10 + 0x308) = 0;
    uVar1 = 0xffffffdf;
  }
  return uVar1;
}

