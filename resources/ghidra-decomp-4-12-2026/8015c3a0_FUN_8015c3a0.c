// Function: FUN_8015c3a0
// Entry: 8015c3a0
// Size: 172 bytes

undefined4
FUN_8015c3a0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  
  iVar1 = *(int *)(*(int *)(param_9 + 0xb8) + 0x40c);
  *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 4;
  *(float *)(param_10 + 0x2a0) = FLOAT_803e39d0;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e39ac,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,5,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 1;
  (**(code **)(*DAT_803dd70c + 0x30))((double)FLOAT_803dc074,param_9,param_10,4);
  return 0;
}

