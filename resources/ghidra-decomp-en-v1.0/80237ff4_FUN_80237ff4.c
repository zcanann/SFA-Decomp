// Function: FUN_80237ff4
// Entry: 80237ff4
// Size: 312 bytes

void FUN_80237ff4(int param_1)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  float *pfVar6;
  
  pfVar6 = *(float **)(param_1 + 0xb8);
  iVar5 = *(int *)(param_1 + 0x4c);
  *(byte *)((int)pfVar6 + 0x26) = *(byte *)((int)pfVar6 + 0x26) & 0x7f;
  if (*(short *)(iVar5 + 0x20) != -1) {
    uVar3 = FUN_8001ffb4();
    *(byte *)((int)pfVar6 + 0x26) =
         (byte)((uVar3 & 0xff) << 7) | *(byte *)((int)pfVar6 + 0x26) & 0x7f;
  }
  if ((((*(short *)(param_1 + 0x46) == 0x29a) || (*(short *)(param_1 + 0x46) == 0x829)) &&
      (*(char *)((int)pfVar6 + 0x26) < '\0')) && (*(short *)(iVar5 + 0x1e) != -1)) {
    uVar4 = FUN_8001ffb4();
    uVar3 = countLeadingZeros(uVar4);
    *(byte *)((int)pfVar6 + 0x26) =
         (byte)((uVar3 >> 5 & 0xff) << 7) | *(byte *)((int)pfVar6 + 0x26) & 0x7f;
  }
  fVar2 = FLOAT_803e73e0;
  fVar1 = FLOAT_803e73d0;
  if ((*(char *)((int)pfVar6 + 0x26) < '\0') && (*pfVar6 < FLOAT_803e73e0)) {
    *pfVar6 = FLOAT_803e7400 * FLOAT_803db414 + *pfVar6;
    if (*pfVar6 <= fVar2) {
      return;
    }
    *pfVar6 = fVar2;
    return;
  }
  if (((-1 < *(char *)((int)pfVar6 + 0x26)) && (FLOAT_803e73d0 < *pfVar6)) &&
     (*pfVar6 = -(FLOAT_803e7400 * FLOAT_803db414 - *pfVar6), *pfVar6 < fVar1)) {
    *pfVar6 = fVar1;
  }
  return;
}

