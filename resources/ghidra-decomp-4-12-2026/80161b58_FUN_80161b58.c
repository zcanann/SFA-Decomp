// Function: FUN_80161b58
// Entry: 80161b58
// Size: 192 bytes

undefined4
FUN_80161b58(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  
  iVar1 = *(int *)(param_9 + 0xb8);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e3b50,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,8,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(float *)(param_10 + 0x2a0) = FLOAT_803e3b80;
  if ((*(uint *)(param_10 + 0x314) & 0x200) != 0) {
    FUN_8000bb38(param_9,0x233);
    *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & 0xfffffdff;
    (**(code **)(*DAT_803dd738 + 0x4c))(param_9,(int)*(short *)(iVar1 + 0x3f0),0xffffffff,1);
  }
  return 0;
}

