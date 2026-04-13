// Function: FUN_801685c4
// Entry: 801685c4
// Size: 260 bytes

undefined4
FUN_801685c4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
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
      *(undefined2 *)(iVar2 + 0x402) = 1;
    }
  }
  else {
    if (!bVar1) {
      FUN_8003042c((double)FLOAT_803e3cf8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,4,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    FUN_8016980c(param_9,1);
    *(undefined *)(param_10 + 0x25f) = 1;
    FUN_800201ac((int)*(short *)(iVar2 + 0x3f4),1);
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
    *(undefined *)(param_9 + 0x36) = 0xff;
    *(undefined *)(param_10 + 0x34d) = 1;
    *(float *)(param_10 + 0x2a0) =
         FLOAT_803e3d30 +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x406)) - DOUBLE_803e3d00) /
         FLOAT_803e3d34;
    FUN_80036018(param_9);
  }
  return 0;
}

