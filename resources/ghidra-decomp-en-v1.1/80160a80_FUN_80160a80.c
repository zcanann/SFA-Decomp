// Function: FUN_80160a80
// Entry: 80160a80
// Size: 188 bytes

undefined4
FUN_80160a80(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)(param_9 + 0xb8);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e3b00,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x25f) = 1;
  *(undefined2 *)(param_9 + 4) = *(undefined2 *)(param_10 + 0x19e);
  *(undefined2 *)(param_9 + 2) = *(undefined2 *)(param_10 + 0x19c);
  (**(code **)(*DAT_803dd738 + 0x10))
            ((double)FLOAT_803e3b24,(double)FLOAT_803e3b28,param_9,param_10,uVar1);
  *(float *)(param_10 + 0x2a0) = FLOAT_803e3b2c * *(float *)(param_10 + 0x280);
  return 0;
}

