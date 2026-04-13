// Function: FUN_80149040
// Entry: 80149040
// Size: 404 bytes

void FUN_80149040(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  *(undefined *)(param_10 + 0x2ef) = 1;
  if (((*(uint *)(param_10 + 0x2dc) & 0x1000) != 0) && ((*(uint *)(param_10 + 0x2e0) & 0x1000) == 0)
     ) {
    *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) & 0xbfff;
    param_2 = (double)*(float *)(param_10 + 0x314);
    if ((double)FLOAT_803e31fc == param_2) {
      *(float *)(param_10 + 0x308) = FLOAT_803e3208;
    }
    else {
      *(float *)(param_10 + 0x308) = FLOAT_803e3200 / (float)((double)FLOAT_803e3204 * param_2);
    }
    *(undefined *)(param_10 + 0x323) = 1;
    FUN_8003042c((double)FLOAT_803e31fc,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,(uint)*(byte *)(param_10 + 800),0x10,param_12,param_13,param_14,param_15,
                 param_16);
    if (*(int *)(param_9 + 0x54) != 0) {
      *(undefined *)(*(int *)(param_9 + 0x54) + 0x70) = 0;
    }
    *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 4;
    FUN_8000b4f0(param_9,1099,2);
    FUN_80036018(param_9);
  }
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) == 0) {
    *(char *)(param_9 + 0x36) = (char)(int)(FLOAT_803e3210 * *(float *)(param_9 + 0x98));
    *(undefined4 *)(param_10 + 0x30c) = *(undefined4 *)(param_9 + 0x98);
  }
  else {
    *(float *)(param_10 + 0x308) = FLOAT_803e320c;
    *(undefined *)(param_10 + 0x323) = 0;
    FUN_8003042c((double)FLOAT_803e31fc,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
    if (*(int *)(param_9 + 0x54) != 0) {
      *(undefined *)(*(int *)(param_9 + 0x54) + 0x70) = 0;
    }
    *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) & 0xffffef7f;
    *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) & 0xfffffffb;
    *(float *)(param_10 + 0x30c) = FLOAT_803e31fc;
    *(undefined *)(param_9 + 0x36) = 0xff;
  }
  return;
}

