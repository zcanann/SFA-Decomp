// Function: FUN_8015c958
// Entry: 8015c958
// Size: 280 bytes

undefined4
FUN_8015c958(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0x5c);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e39ac,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,9,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  iVar1 = *(int *)(iVar2 + 0x40c);
  *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 0xc;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 8;
    *(undefined2 *)(iVar2 + 0x402) = 4;
  }
  *param_9 = (short)(int)(FLOAT_803e39f4 *
                          (((float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)(param_10 + 0x336) ^ 0x80000000)
                                   - DOUBLE_803e3a00) * FLOAT_803dc074) / FLOAT_803e39f8) +
                         (float)((double)CONCAT44(0x43300000,(int)*param_9 ^ 0x80000000) -
                                DOUBLE_803e3a00));
  *(float *)(param_10 + 0x2a0) = FLOAT_803e39d0;
  *(float *)(param_10 + 0x280) = FLOAT_803e39e0;
  return 0;
}

