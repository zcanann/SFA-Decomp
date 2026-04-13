// Function: FUN_802386b8
// Entry: 802386b8
// Size: 312 bytes

void FUN_802386b8(int param_1)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  float *pfVar5;
  
  pfVar5 = *(float **)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x4c);
  *(byte *)((int)pfVar5 + 0x26) = *(byte *)((int)pfVar5 + 0x26) & 0x7f;
  uVar3 = (uint)*(short *)(iVar4 + 0x20);
  if (uVar3 != 0xffffffff) {
    uVar3 = FUN_80020078(uVar3);
    *(byte *)((int)pfVar5 + 0x26) =
         (byte)((uVar3 & 0xff) << 7) | *(byte *)((int)pfVar5 + 0x26) & 0x7f;
  }
  if ((((*(short *)(param_1 + 0x46) == 0x29a) || (*(short *)(param_1 + 0x46) == 0x829)) &&
      (*(char *)((int)pfVar5 + 0x26) < '\0')) &&
     (uVar3 = (uint)*(short *)(iVar4 + 0x1e), uVar3 != 0xffffffff)) {
    uVar3 = FUN_80020078(uVar3);
    uVar3 = countLeadingZeros(uVar3);
    *(byte *)((int)pfVar5 + 0x26) =
         (byte)((uVar3 >> 5 & 0xff) << 7) | *(byte *)((int)pfVar5 + 0x26) & 0x7f;
  }
  fVar2 = FLOAT_803e8078;
  fVar1 = FLOAT_803e8068;
  if ((*(char *)((int)pfVar5 + 0x26) < '\0') && (*pfVar5 < FLOAT_803e8078)) {
    *pfVar5 = FLOAT_803e8098 * FLOAT_803dc074 + *pfVar5;
    if (*pfVar5 <= fVar2) {
      return;
    }
    *pfVar5 = fVar2;
    return;
  }
  if (((-1 < *(char *)((int)pfVar5 + 0x26)) && (FLOAT_803e8068 < *pfVar5)) &&
     (*pfVar5 = -(FLOAT_803e8098 * FLOAT_803dc074 - *pfVar5), *pfVar5 < fVar1)) {
    *pfVar5 = fVar1;
  }
  return;
}

