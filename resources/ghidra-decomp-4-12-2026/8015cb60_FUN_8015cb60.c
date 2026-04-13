// Function: FUN_8015cb60
// Entry: 8015cb60
// Size: 276 bytes

undefined4
FUN_8015cb60(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  
  iVar1 = *(int *)(param_9 + 0xb8);
  if ((*(short *)(param_10 + 0x276) != 4) && (*(char *)(param_10 + 0x27a) != '\0')) {
    FUN_8003042c((double)FLOAT_803e39ac,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0xe,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(byte *)(*(int *)(iVar1 + 0x40c) + 0x44) = *(byte *)(*(int *)(iVar1 + 0x40c) + 0x44) | 0xc;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) =
         *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) & 0xfffe;
    *(float *)(param_10 + 0x2a0) = FLOAT_803e39d0;
    *(float *)(param_10 + 0x280) = FLOAT_803e39ac;
  }
  if (*(char *)(param_10 + 0x346) != '\0') {
    FUN_800201ac((int)*(short *)(iVar1 + 0x3f4),0);
    FUN_8003042c((double)FLOAT_803e39ac,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,8,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined4 *)(param_10 + 0x2d0) = 0;
    *(undefined *)(param_10 + 0x25f) = 0;
    *(undefined *)(param_10 + 0x349) = 0;
    *(undefined2 *)(iVar1 + 0x402) = 0;
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
  }
  return 0;
}

