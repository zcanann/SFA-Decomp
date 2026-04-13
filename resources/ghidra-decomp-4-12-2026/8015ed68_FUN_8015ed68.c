// Function: FUN_8015ed68
// Entry: 8015ed68
// Size: 396 bytes

undefined4
FUN_8015ed68(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  iVar1 = *(int *)(iVar2 + 0x40c);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e3a60,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0xb,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  if (*(char *)(param_10 + 0x27a) == '\0') {
    FUN_80035eec(param_9,10,1,-1);
    *(undefined *)(*(int *)(param_9 + 0x54) + 0x6c) = 10;
    *(undefined *)(*(int *)(param_9 + 0x54) + 0x6d) = 1;
    FUN_80033a34(param_9);
  }
  else {
    *(undefined *)(param_10 + 0x25f) = 1;
    FUN_800201ac((int)*(short *)(iVar2 + 0x3f4),1);
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
    *(undefined *)(param_9 + 0x36) = 0xff;
    *(undefined *)(param_10 + 0x34d) = 1;
    *(float *)(param_10 + 0x2a0) =
         FLOAT_803e3a80 +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x406)) - DOUBLE_803e3a58) /
         FLOAT_803e3a84;
    FUN_80036018(param_9);
  }
  if (*(char *)(param_10 + 0x346) != '\0') {
    *(undefined2 *)(iVar2 + 0x402) = 1;
  }
  if ((*(uint *)(param_10 + 0x314) & 0x200) != 0) {
    *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & 0xfffffdff;
    *(byte *)(iVar1 + 8) = *(byte *)(iVar1 + 8) | 4;
  }
  if (*(float *)(param_9 + 0x98) < FLOAT_803e3a88) {
    *(byte *)(iVar1 + 8) = *(byte *)(iVar1 + 8) | 2;
  }
  return 0;
}

