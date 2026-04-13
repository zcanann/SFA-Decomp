// Function: FUN_80213cb8
// Entry: 80213cb8
// Size: 156 bytes

undefined4
FUN_80213cb8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,int param_10
            ,undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e7450,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,(int)*(short *)(&DAT_803dceb8 + (uint)*(byte *)(DAT_803de9d4 + 0xfc) * 2),0
                 ,param_12,param_13,param_14,param_15,param_16);
    *(float *)(param_10 + 0x2a0) = FLOAT_803e74a8;
    fVar1 = FLOAT_803e7450;
    *(float *)(param_10 + 0x280) = FLOAT_803e7450;
    *(float *)(param_10 + 0x284) = fVar1;
  }
  if ((*(uint *)(DAT_803de9d8 + 0x314) & 1) != 0) {
    *(uint *)(DAT_803de9d8 + 0x314) = *(uint *)(DAT_803de9d8 + 0x314) & 0xfffffffe;
    *(uint *)(DAT_803de9d4 + 0x104) = *(uint *)(DAT_803de9d4 + 0x104) | 0x200;
  }
  return 0;
}

