// Function: FUN_8015ec44
// Entry: 8015ec44
// Size: 292 bytes

undefined4
FUN_8015ec44(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  int unaff_r29;
  int iVar1;
  
  iVar1 = *(int *)(param_9 + 0xb8);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e3a60,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0xe,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  if (FLOAT_803e3a7c < *(float *)(param_9 + 0x98)) {
    unaff_r29 = *(int *)(iVar1 + 0x40c);
    *(byte *)(unaff_r29 + 8) = *(byte *)(unaff_r29 + 8) | 2;
  }
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_80035ff8(param_9);
    *(float *)(param_10 + 0x2a0) = FLOAT_803e3a70;
    *(float *)(param_10 + 0x280) = FLOAT_803e3a60;
  }
  if (*(char *)(param_10 + 0x346) != '\0') {
    FUN_800201ac((int)*(short *)(iVar1 + 0x3f4),0);
    FUN_8003042c((double)FLOAT_803e3a60,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,8,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined4 *)(param_10 + 0x2d0) = 0;
    *(undefined *)(param_10 + 0x25f) = 0;
    *(undefined *)(param_10 + 0x349) = 0;
    *(undefined2 *)(iVar1 + 0x402) = 0;
    if ((*(byte *)(unaff_r29 + 9) & 2) == 0) {
      *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
    }
  }
  return 0;
}

