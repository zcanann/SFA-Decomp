// Function: FUN_80213a68
// Entry: 80213a68
// Size: 200 bytes

undefined4
FUN_80213a68(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e7450,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0xd,0,param_12,param_13,param_14,param_15,param_16);
    *(float *)(param_10 + 0x2a0) =
         FLOAT_803e7490 *
         (float)((double)CONCAT44(0x43300000,
                                  (int)(uint)*(byte *)(DAT_803de9d4 + 0x101) >> 1 ^ 0x80000000) -
                DOUBLE_803e7498) + FLOAT_803e748c;
    FUN_8000bb38(param_9,0x88);
  }
  if ((*(uint *)(DAT_803de9d8 + 0x314) & 1) != 0) {
    *(uint *)(DAT_803de9d8 + 0x314) = *(uint *)(DAT_803de9d8 + 0x314) & 0xfffffffe;
    *(uint *)(DAT_803de9d4 + 0x104) = *(uint *)(DAT_803de9d4 + 0x104) | 0x2000;
  }
  return 0;
}

