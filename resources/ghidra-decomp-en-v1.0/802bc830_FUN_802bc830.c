// Function: FUN_802bc830
// Entry: 802bc830
// Size: 480 bytes

undefined4 FUN_802bc830(int param_1,int param_2,int param_3)

{
  float fVar1;
  
  *(uint *)(param_2 + 0x360) = *(uint *)(param_2 + 0x360) | 0x1000000;
  *(float *)(param_3 + 0x2a0) = FLOAT_803e82ec;
  if ((((FLOAT_803e82f0 < *(float *)(param_1 + 0x98)) &&
       (*(float *)(param_1 + 0x98) < FLOAT_803e82f4)) &&
      (*(float *)(*(int *)(param_2 + 0x400) + 0x1c) - FLOAT_803e82f8 < *(float *)(param_3 + 0x294)))
     && ((FLOAT_803e82fc < *(float *)(param_3 + 0x298) && (0x95 < *(int *)(param_2 + 0x488))))) {
    *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xbf | 0x40;
    *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0x7f;
    *(undefined *)(param_2 + 0x8a6) = *(undefined *)(param_2 + 0x8a7);
    *(float *)(param_3 + 0x2a0) = FLOAT_803e8300;
    FUN_80030334((double)FLOAT_803e8304,param_1,(int)*(short *)(*(int *)(param_2 + 0x3f8) + 0x3a),0)
    ;
    FUN_8002f574(param_1,0x10);
    *(int *)(param_2 + 0x858) = (int)*(short *)(param_2 + 0x484);
    *(float *)(param_2 + 0x844) =
         (FLOAT_803e8308 +
         *(float *)(*(int *)(param_2 + 0x400) + 0x14) + *(float *)(param_3 + 0x294)) /
         FLOAT_803e830c;
    *(undefined2 *)(param_2 + 0x478) = *(undefined2 *)(param_2 + 0x484);
    *(short *)(param_2 + 0x484) = *(short *)(param_2 + 0x484) + -0x8000;
    *(float *)(param_3 + 0x294) = -*(float *)(param_3 + 0x294);
    *(float *)(param_3 + 0x280) = -*(float *)(param_3 + 0x280);
  }
  if (*(char *)(param_2 + 0x3f0) < '\0') {
    fVar1 = *(float *)(*(int *)(param_2 + 0x400) + 0x10);
    if ((*(float *)(param_3 + 0x294) <= fVar1) && (*(float *)(param_3 + 0x280) <= fVar1)) {
      *(int *)(param_2 + 0x494) = (int)*(short *)(param_2 + 0x484);
      *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xbf;
      *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0x7f;
      return 1;
    }
    *(float *)(param_2 + 0x408) = FLOAT_803e8304;
    *(undefined4 *)(param_2 + 0x438) = *(undefined4 *)(param_2 + 0x830);
    *(ushort *)(param_2 + 0x8d8) = *(ushort *)(param_2 + 0x8d8) | 8;
  }
  return 0;
}

