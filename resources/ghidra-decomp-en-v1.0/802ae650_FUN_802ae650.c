// Function: FUN_802ae650
// Entry: 802ae650
// Size: 492 bytes

void FUN_802ae650(int param_1,int param_2,int param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  
  (**(code **)(*DAT_803dca8c + 0x20))((double)FLOAT_803db414,param_1,param_3,1);
  fVar3 = FLOAT_803e7ee0;
  if (-(FLOAT_803e7f50 * *(float *)(param_3 + 0x2a0) - FLOAT_803e7ee0) <= *(float *)(param_1 + 0x98)
     ) {
    *(float *)(param_3 + 0x280) =
         *(float *)(param_2 + 0x844) *
         ((FLOAT_803e7f14 + *(float *)(*(int *)(param_2 + 0x400) + 0x14)) -
         *(float *)(param_3 + 0x280)) + *(float *)(param_3 + 0x280);
    *(undefined4 *)(param_3 + 0x294) = *(undefined4 *)(param_3 + 0x280);
    *(float *)(param_2 + 0x844) = FLOAT_803e7efc * FLOAT_803db414 + *(float *)(param_2 + 0x844);
    fVar1 = *(float *)(param_2 + 0x844);
    fVar2 = FLOAT_803e7ea4;
    if ((FLOAT_803e7ea4 <= fVar1) && (fVar2 = fVar1, fVar3 < fVar1)) {
      fVar2 = fVar3;
    }
    *(float *)(param_2 + 0x844) = fVar2;
  }
  if ((*(uint *)(param_3 + 0x314) & 0x200) != 0) {
    FUN_80014aa0((double)FLOAT_803e7f10);
    FUN_8000bb18(param_1,0x3cd);
    *(ushort *)(param_2 + 0x8d8) = *(ushort *)(param_2 + 0x8d8) | 4;
  }
  fVar3 = FLOAT_803e7fa4;
  *(float *)(param_2 + 0x428) = FLOAT_803e7fa4;
  *(float *)(param_2 + 0x430) = fVar3;
  fVar1 = FLOAT_803e7ed4;
  fVar3 = FLOAT_803e7ea4;
  if ((*(byte *)(param_2 + 0x3f1) >> 4 & 1) == 0) {
    *(float *)(param_2 + 0x42c) = FLOAT_803e7ed4;
    *(float *)(param_2 + 0x434) = fVar1;
  }
  else {
    *(float *)(param_2 + 0x42c) = FLOAT_803e7ea4;
    *(float *)(param_2 + 0x434) = fVar3;
  }
  *(float *)(param_2 + 0x7a4) = FLOAT_803e80e4;
  if (FLOAT_803e7ee0 <= *(float *)(param_1 + 0x98)) {
    *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xef;
    DAT_803dc66c = 1;
    *(byte *)(param_2 + 0x3f1) = *(byte *)(param_2 + 0x3f1) & 0xfd | 2;
    *(byte *)(param_2 + 0x3f1) = *(byte *)(param_2 + 0x3f1) & 0xf7 | 8;
    *(undefined *)(param_2 + 0x8cc) = 0xc;
    *(short *)(param_2 + 0x478) = *(short *)(param_2 + 0x484);
    *(int *)(param_2 + 0x494) = (int)*(short *)(param_2 + 0x484);
    FUN_80030334((double)FLOAT_803e7ea4,param_1,
                 (int)*(short *)(&DAT_80333050 + *(char *)(param_2 + 0x8cc) * 2),0);
    FUN_8002f574(param_1,1);
  }
  return;
}

