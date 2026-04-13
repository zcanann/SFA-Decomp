// Function: FUN_802aebe0
// Entry: 802aebe0
// Size: 464 bytes

undefined4
FUN_802aebe0(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            int param_10,int param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  
  *(uint *)(param_10 + 0x360) = *(uint *)(param_10 + 0x360) | 0x1000000;
  *(float *)(param_11 + 0x2a0) = FLOAT_803e8bb8;
  if ((((FLOAT_803e8b94 < *(float *)(param_9 + 0x98)) &&
       (*(float *)(param_9 + 0x98) < FLOAT_803e8bdc)) &&
      (fVar1 = *(float *)(param_11 + 0x294),
      (double)(*(float *)(*(int *)(param_10 + 0x400) + 0x1c) - FLOAT_803e8b34) < (double)fVar1)) &&
     ((FLOAT_803e8bc4 < *(float *)(param_11 + 0x298) && (0x95 < *(int *)(param_10 + 0x488))))) {
    *(byte *)(param_10 + 0x3f0) = *(byte *)(param_10 + 0x3f0) & 0xbf | 0x40;
    *(byte *)(param_10 + 0x3f0) = *(byte *)(param_10 + 0x3f0) & 0x7f;
    *(undefined *)(param_10 + 0x8a6) = *(undefined *)(param_10 + 0x8a7);
    *(float *)(param_11 + 0x2a0) = FLOAT_803e8d08;
    FUN_8003042c((double)FLOAT_803e8b3c,(double)fVar1,param_3,param_4,param_5,param_6,param_7,
                 param_8,param_9,(int)*(short *)(*(int *)(param_10 + 0x3f8) + 0x3a),0,param_12,
                 param_13,param_14,param_15,param_16);
    FUN_8002f66c(param_9,0x10);
    *(int *)(param_10 + 0x858) = (int)*(short *)(param_10 + 0x484);
    *(float *)(param_10 + 0x844) =
         (FLOAT_803e8bac +
         *(float *)(*(int *)(param_10 + 0x400) + 0x14) + *(float *)(param_11 + 0x294)) /
         FLOAT_803e8bc8;
    *(undefined2 *)(param_10 + 0x478) = *(undefined2 *)(param_10 + 0x484);
    *(short *)(param_10 + 0x484) = *(short *)(param_10 + 0x484) + -0x8000;
    *(float *)(param_11 + 0x294) = -*(float *)(param_11 + 0x294);
    *(float *)(param_11 + 0x280) = -*(float *)(param_11 + 0x280);
  }
  if (*(char *)(param_10 + 0x3f0) < '\0') {
    fVar1 = *(float *)(*(int *)(param_10 + 0x400) + 0x10);
    if ((*(float *)(param_11 + 0x294) <= fVar1) && (*(float *)(param_11 + 0x280) <= fVar1)) {
      *(int *)(param_10 + 0x494) = (int)*(short *)(param_10 + 0x484);
      *(byte *)(param_10 + 0x3f0) = *(byte *)(param_10 + 0x3f0) & 0xbf;
      *(byte *)(param_10 + 0x3f0) = *(byte *)(param_10 + 0x3f0) & 0x7f;
      return 1;
    }
    *(float *)(param_10 + 0x408) = FLOAT_803e8b3c;
    *(undefined4 *)(param_10 + 0x438) = *(undefined4 *)(param_10 + 0x830);
  }
  return 0;
}

