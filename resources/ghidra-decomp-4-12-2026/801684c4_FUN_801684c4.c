// Function: FUN_801684c4
// Entry: 801684c4
// Size: 256 bytes

undefined4
FUN_801684c4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  bool bVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  bVar1 = *(char *)(param_10 + 0x27a) == '\0';
  if (bVar1) {
    if (*(char *)(param_10 + 0x346) != '\0') {
      FUN_800201ac((int)*(short *)(iVar2 + 0x3f4),0);
      if (*(char *)(param_10 + 0x27a) != '\0') {
        FUN_8003042c((double)FLOAT_803e3cf8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,4,0,param_12,param_13,param_14,param_15,param_16);
        *(undefined *)(param_10 + 0x346) = 0;
      }
      *(undefined2 *)(iVar2 + 0x402) = 0;
    }
  }
  else {
    if (!bVar1) {
      FUN_8003042c((double)FLOAT_803e3cf8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,5,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    FUN_80035ff8(param_9);
    *(float *)(param_10 + 0x2a0) = FLOAT_803e3d14;
    *(float *)(param_10 + 0x280) = FLOAT_803e3cf8;
  }
  if ((*(uint *)(param_10 + 0x314) & 0x1000) != 0) {
    *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & 0xffffefff;
    FUN_8016980c(param_9,2);
  }
  return 0;
}

