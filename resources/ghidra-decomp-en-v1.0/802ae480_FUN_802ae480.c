// Function: FUN_802ae480
// Entry: 802ae480
// Size: 464 bytes

undefined4 FUN_802ae480(int param_1,int param_2,int param_3)

{
  float fVar1;
  
  *(uint *)(param_2 + 0x360) = *(uint *)(param_2 + 0x360) | 0x1000000;
  *(float *)(param_3 + 0x2a0) = FLOAT_803e7f20;
  if ((((FLOAT_803e7efc < *(float *)(param_1 + 0x98)) &&
       (*(float *)(param_1 + 0x98) < FLOAT_803e7f44)) &&
      (*(float *)(*(int *)(param_2 + 0x400) + 0x1c) - FLOAT_803e7e9c < *(float *)(param_3 + 0x294)))
     && ((FLOAT_803e7f2c < *(float *)(param_3 + 0x298) && (0x95 < *(int *)(param_2 + 0x488))))) {
    *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xbf | 0x40;
    *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0x7f;
    *(undefined *)(param_2 + 0x8a6) = *(undefined *)(param_2 + 0x8a7);
    *(float *)(param_3 + 0x2a0) = FLOAT_803e8070;
    FUN_80030334((double)FLOAT_803e7ea4,param_1,(int)*(short *)(*(int *)(param_2 + 0x3f8) + 0x3a),0)
    ;
    FUN_8002f574(param_1,0x10);
    *(int *)(param_2 + 0x858) = (int)*(short *)(param_2 + 0x484);
    *(float *)(param_2 + 0x844) =
         (FLOAT_803e7f14 +
         *(float *)(*(int *)(param_2 + 0x400) + 0x14) + *(float *)(param_3 + 0x294)) /
         FLOAT_803e7f30;
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
    *(float *)(param_2 + 0x408) = FLOAT_803e7ea4;
    *(undefined4 *)(param_2 + 0x438) = *(undefined4 *)(param_2 + 0x830);
  }
  return 0;
}

